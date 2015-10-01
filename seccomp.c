#include <linux/filter.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "imgset.h"
#include "kcmp.h"
#include "pstree.h"
#include "ptrace.h"
#include "proc_parse.h"
#include "seccomp.h"
#include "servicefd.h"
#include "util.h"

#include "protobuf.h"
#include "protobuf/seccomp.pb-c.h"

/* populated on dump during collect_seccomp_filters() */
static int next_filter_id = 0;

static struct seccomp_info *find_inherited(struct pstree_item *parent, int filter)
{
	struct seccomp_info *info = dmpi(parent)->pi_creds->last_filter;
	pid_t pid = getpid();

	while (info) {

		if (!sys_kcmp(pid, pid, KCMP_SECCOMP_FD, filter, info->fd))
			return info;

		info = info->prev;
	}

	return NULL;
}

static int collect_filter_for_pstree(struct pstree_item *item)
{
	struct seccomp_info *filters = NULL, *cursor;
	int filter_count, i, ret = -1;

	if (dmpi(item)->pi_creds->seccomp_mode != SECCOMP_MODE_FILTER)
		return 0;

	for (i = 0; true; i++) {
		int fd;
		struct seccomp_info *filter, *inherited = NULL;

		fd = ptrace(PTRACE_SECCOMP_GET_FILTER_FD, item->pid.real, NULL, i);
		if (fd < 0) {
			if (errno == EINVAL) {
				if (!filters) {
					pr_err("dumping seccomp filters not supported\n");
					return -1;
				}

				/* end of the search */
				goto save_filters;
			} else
				goto out;
		}

		inherited = find_inherited(item->parent, fd);
		if (inherited) {
			close(fd);

			/* If this is the first filter, we're simply inheriting
			 * everything. If it's not, then we should set the
			 * inherited filter to the parent of the filter at the
			 * top of this chain.
			 */
			if (!filters) {
				filters = inherited;
			} else {
				for (cursor = filters; cursor->prev; cursor = cursor->prev)
					;
				cursor->prev = inherited;
			}

			goto save_filters;
		}

		filter = xmalloc(sizeof(*filter));
		if (!filter)
			goto out;

		filter->fd = fd;
		filter->prev = filters;
		filters = filter;
	}

save_filters:
	filter_count = i;

	for (cursor = filters, i = filter_count + next_filter_id - 1;
	     i >= next_filter_id; i--) {
		BUG_ON(!cursor);
		cursor->id = i;
		cursor = cursor->prev;
	}

	next_filter_id += filter_count;

	dmpi(item)->pi_creds->last_filter = filters;

	/* Don't free the part of the tree we just successfully acquired */
	filters = NULL;
	ret = 0;
out:
	while (filters) {
		struct seccomp_info *freeme = filters;
		filters = filters->prev;
		xfree(freeme);
	}

	return ret;
}

static int dump_seccomp_info(struct seccomp_info *info, SeccompFilter **filters)
{
	int len;
	cr_seccomp_fd fd;
	struct sock_filter insns[BPF_MAXINSNS];
	SeccompFilter *filter;

	if (filters[info->id])
		return 1;

	fd.size = sizeof(fd);
	fd.dump_fd = info->fd;
	fd.insns = insns;

	len = sys_seccomp(SECCOMP_FILTER_FD, SECCOMP_FD_DUMP, (char *) &fd);
	close_safe(&info->fd);
	if (len < 0) {
		pr_perror("seccomp fd dump failed");
		return -1;
	}

	BUG_ON(len % sizeof(insns[0]));

	filter = filters[info->id] = xmalloc(sizeof(*filter));
	if (!filter)
		return -1;
	seccomp_filter__init(filter);

	if (info->prev) {
		filter->has_prev = true;
		filter->prev = info->prev->id;
	}

	filter->filter.data = xmalloc(len);
	if (!filter->filter.data) {
		xfree(filter);
		return -1;
	}
	filter->filter.len = len;

	memcpy(filter->filter.data, fd.insns, len);
	return 0;
}

static int dump_seccomp_filters(void)
{
	struct pstree_item *item;
	SeccompEntry se = SECCOMP_ENTRY__INIT;
	int ret = -1, i;

	/* If we didn't collect any filters, don't create a seccomp image at all. */
	if (next_filter_id == 0)
		return 0;

	se.seccomp_filters = xzalloc(sizeof(*se.seccomp_filters) * next_filter_id);
	if (!se.seccomp_filters)
		return -1;
	se.n_seccomp_filters = next_filter_id;

	for_each_pstree_item(item) {
		struct seccomp_info *cursor;

		for (cursor = dmpi(item)->pi_creds->last_filter; cursor; cursor = cursor->prev) {
			ret = dump_seccomp_info(cursor, se.seccomp_filters);
			if (ret < 0)
				goto out;
			/* these filters were already dumped */
			if (ret > 0)
				break;
		}
	}

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SECCOMP), &se, PB_SECCOMP);

out:
	for (i = 0; i < next_filter_id; i++) {
		if (!se.seccomp_filters[i])
			break;

		if (se.seccomp_filters[i]->filter.data)
			xfree(se.seccomp_filters[i]->filter.data);

		xfree(se.seccomp_filters[i]);
	}

	xfree(se.seccomp_filters);

	return ret;
}

int collect_seccomp_filters(void)
{
	if (preorder_pstree_traversal(root_item, collect_filter_for_pstree) < 0)
		return -1;

	if (dump_seccomp_filters())
		return -1;

	return 0;
}

/* Populated on restore by prepare_seccomp_filters */
static pid_t seccomp_filterd = 0;

/* seccomp(SECCOMP_FILTER_FD, SECCOMP_FD_NEW, ...) requires us to pass the
 * parent seccomp fd at creation time. So, we need to find all the parents
 * first and initialize them. Here's a helper to do that.
 */
static int initialize_seccomp_chain(SeccompEntry *se, int *fds, uint32_t prog_id)
{
	SeccompFilter *sf = se->seccomp_filters[prog_id];
	struct seccomp_fd fd;
	struct sock_fprog fprog;

	if (fds[prog_id] >= 0)
		return 0;

	if (sf->has_prev && initialize_seccomp_chain(se, fds, sf->prev) < 0)
		return -1;

	fd.size = sizeof(fd);
	fd.new_prog = &fprog;

	BUG_ON(sf->filter.len % sizeof(struct sock_filter));
	fprog.len = sf->filter.len / sizeof(struct sock_filter);
	fprog.filter = (struct sock_filter *) sf->filter.data;

	fd.new_parent = -1;
	if (sf->has_prev) {
		BUG_ON(fds[sf->prev] < 0);
		fd.new_parent = fds[sf->prev];
	}

	fds[prog_id] = sys_seccomp(SECCOMP_FILTER_FD, SECCOMP_FD_NEW, (char *) &fd);
	if (fds[prog_id] < 0) {
		errno = -fds[prog_id];
		pr_perror("importing seccomp program failed");
		return -1;
	}

	return 0;
}

static int run_seccomp_filterd(struct cr_img *img, int sock)
{
	uint32_t i;
	int ret;
	int *fds = NULL;
	SeccompEntry *se = NULL;

	ret = pb_read_one_eof(img, &se, PB_SECCOMP);
	close_image(img);
	if (ret < 0)
		return -1;

	BUG_ON(!se);

	fds = xmalloc(sizeof(*fds) * se->n_seccomp_filters);
	if (!fds)
		return -1;

	memset(fds, 0xff, sizeof(*fds) * se->n_seccomp_filters);

	for (i = 0; i < se->n_seccomp_filters; i++) {
		if (initialize_seccomp_chain(se, fds, i) < 0)
			goto err;
	}

	/* wait until we are killed */
	while (1) {
		struct msghdr hdr;
		struct iovec iov;
		int filter_id;
		char c[CMSG_SPACE(sizeof(int))];
		struct cmsghdr *ch;

		hdr.msg_name = NULL;
		hdr.msg_namelen = 0;
		hdr.msg_flags = 0;

		hdr.msg_control = 0;
		hdr.msg_controllen = 0;
		hdr.msg_iov = &iov;
		hdr.msg_iovlen = 1;
		iov.iov_base = &filter_id;
		iov.iov_len = sizeof(filter_id);

		if (recvmsg(sock, &hdr, 0) <= 0) {
			pr_perror("bad seccompd msg");
			goto err;
		}

		if (iov.iov_len != sizeof(int)) {
			pr_err("bad msg size %ld\n", iov.iov_len);
			goto err;
		}

		if (filter_id >= se->n_seccomp_filters) {
			pr_err("bad filter id %d\n", filter_id);
			goto err;
		}

		hdr.msg_control = c;
		hdr.msg_controllen = sizeof(c);
		ch = CMSG_FIRSTHDR(&hdr);
		ch->cmsg_len = CMSG_LEN(sizeof(int));
		ch->cmsg_level = SOL_SOCKET;
		ch->cmsg_type = SCM_RIGHTS;
		*((int *)CMSG_DATA(ch)) = fds[filter_id];

		if (sendmsg(sock, &hdr, 0) <= 0) {
			pr_perror("seccompd send msg failed");
			goto err;
		}
	}

err:
	for (i = 0; i < se->n_seccomp_filters; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}

	seccomp_entry__free_unpacked(se, NULL);
	exit(-1);
}

/* For now, we open /all/ of the seccomp fds in the root task, and just inherit
 * them all (and close them all) further on down the tree as needed. However,
 * this is not ideal: if the total number of filters across all tasks is large,
 * we'll need a large number of fds. The assumption here is that the number of
 * filters (note: multiple tasks can point to the same filter) is small since
 * most sandboxes probably have at most one or two policies installed.
 */
int prepare_seccomp_filters(void)
{
	int sk[2];
	struct cr_img *img;

	img = open_image(CR_FD_SECCOMP, O_RSTR);
	if (!img)
		return 0; /* there were no filters */

	/* Same options as usernsd socket, see that for details */
	if (socketpair(PF_UNIX, SOCK_SEQPACKET, 0, sk)) {
		pr_perror("Can't make seccompd socket");
		goto err_img;
	}

	seccomp_filterd = fork();
	if (seccomp_filterd < 0) {
		pr_perror("can't fork seccompd");
		goto err_sk;
	}

	if (!seccomp_filterd) {
		close(sk[0]);
		exit(run_seccomp_filterd(img, sk[1]));
	}

	if (install_service_fd(SECCOMPD_SK, sk[0]) < 0) {
		kill(seccomp_filterd, SIGKILL);
		waitpid(seccomp_filterd, NULL, 0);
		goto err_sk;
	}

	close(sk[1]);

	return 0;

err_sk:
	close(sk[0]);
	close(sk[1]);
err_img:
	close_image(img);
	return -1;
}

int get_seccomp_fd(struct pstree_item *item, CoreEntry *core)
{
	int ret = -1, sk, fd = -1;;
	struct rst_info *ri = rsti(item);
	struct msghdr hdr;
	struct iovec iov;
	struct cmsghdr *ch;
	char buf[CMSG_SPACE(sizeof(int))];

	if (core->tc->seccomp_mode != SECCOMP_MODE_FILTER) {
		ri->seccomp_fd = -1;
		return 0;
	}

	BUG_ON(seccomp_filterd < 0);
	sk = get_service_fd(SECCOMPD_SK);

	BUG_ON(!core->tc->has_seccomp_filter);
	hdr.msg_name = NULL;
	hdr.msg_namelen = 0;
	hdr.msg_flags = 0;
	hdr.msg_controllen = 0;

	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	iov.iov_base = &core->tc->seccomp_filter;
	iov.iov_len = sizeof(core->tc->seccomp_filter);

	if (sendmsg(sk, &hdr, 0) <= 0) {
		pr_perror("send seccomp msg failed");
		goto out;
	}

	hdr.msg_controllen = sizeof(buf);
	hdr.msg_control = buf;

	if (recvmsg(sk, &hdr, 0) <= 0) {
		pr_perror("recv seccomp msg failed");
		goto out;
	}

	ch = CMSG_FIRSTHDR(&hdr);
	if (ch && ch->cmsg_len == CMSG_LEN(sizeof(int))) {
		BUG_ON(ch->cmsg_level != SOL_SOCKET);
		BUG_ON(ch->cmsg_type != SCM_RIGHTS);
		fd = *((int *)CMSG_DATA(ch));
	}

	if (fd < 0) {
		pr_err("didn't get fd back from seccompd msg\n");
		goto out;
	}

	ri->seccomp_fd = fd;
	ret = 0;

out:
	return ret;
}

int stop_seccompd(void)
{
	if (seccomp_filterd <= 0)
		return 0;

	int status = -1;
	sigset_t blockmask, oldmask;

	close_service_fd(SECCOMPD_SK);

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &blockmask, &oldmask);

	kill(seccomp_filterd, SIGKILL);
	waitpid(seccomp_filterd, &status, 0);
	sigprocmask(SIG_BLOCK, &oldmask, NULL);

	seccomp_filterd = 0;

	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		pr_err("abnormal seccompd exit %d\n", status);
		return -1;
	}

	return 0;
}
