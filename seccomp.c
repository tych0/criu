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

static struct seccomp_info *find_inherited(struct pstree_item *parent,
					   struct sock_filter *filter, int len)
{
	struct seccomp_info *info = dmpi(parent)->pi_creds->last_filter;

	for (info = dmpi(parent)->pi_creds->last_filter; info; info = info->prev)

		if (len != info->filter->len)
			continue;
		if (!memcmp(filter, info->filter->data, len))
			return info;
	}

	return NULL;
}

static int collect_filter_for_pstree(struct pstree_item *item)
{
	struct seccomp_info *infos = NULL, *cursor;
	int info_count, i, ret = -1;
	struct sock_filter buf[BPF_MAXINSNS];

	if (dmpi(item)->pi_creds->seccomp_mode != SECCOMP_MODE_FILTER)
		return 0;

	for (i = 0; true; i++) {
		int len;
		struct seccomp_info *filter, *inherited = NULL;

		len = ptrace(PTRACE_SECCOMP_GET_FILTER, item->pid.real, buf, i);
		if (len < 0) {
			if (errno == ENOENT) {
				/* end of the search */
				BUG_ON(i == 0);
				goto save_infos;
			} else if (errno == EINVAL) {
				pr_err("dumping seccomp infos not supported\n");
				goto out;
			} else {
				pr_perror("couldn't dump seccomp filter");
				goto out;
			}
		}

		inherited = find_inherited(item->parent, buf, len);
		if (inherited) {
			/* If this is the first filter, we're simply inheriting
			 * everything. If it's not, then we should set the
			 * inherited filter to the parent of the filter at the
			 * top of this chain.
			 */
			if (!infos) {
				infos = inherited;
			} else {
				for (cursor = infos; cursor->prev; cursor = cursor->prev)
					;
				cursor->prev = inherited;
			}

			goto save_filters;
		}

		filter = xmalloc(sizeof(*filter));
		if (!filter)
			goto out;

		filter->filter.len = len * sizeof(struct sock_filter)
		filter->filter.data = xmalloc(filter->filter.len);
		if (!filter->filter->data)
			goto out;

		memcpy(filter->filter.data, buf, filter->filter.len);

		filter->prev = infos;
		infos = filter;
	}

save_infos:
	info_count = i;

	for (cursor = infos, i = info_count + next_filter_id - 1;
	     i >= next_filter_id; i--) {
		BUG_ON(!cursor);
		cursor->id = i;
		cursor = cursor->prev;
	}

	next_filter_id += info_count;

	dmpi(item)->pi_creds->last_filter = infos;

	/* Don't free the part of the tree we just successfully acquired */
	infos = NULL;
	ret = 0;
out:
	while (infos) {
		struct seccomp_info *freeme = infos;
		infos = infos->prev;
		xfree(freeme->filter.data);
		xfree(freeme);
	}

	return ret;
}

static int dump_seccomp_info(struct seccomp_info *info, SeccompFilter **filters)
{
	int len;
	SeccompFilter *filter;

	if (filters[info->id])
		return 1;

	filter = filters[info->id] = xmalloc(sizeof(*filter));
	if (!filter)
		return -1;
	seccomp_filter__init(filter);

	if (info->prev) {
		filter->has_prev = true;
		filter->prev = info->prev->id;
	}

	filter->filter = info->filter;

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
static SeccompEntry *se;

/* For now, we open /all/ of the seccomp fds in the root task, and just inherit
 * them all (and close them all) further on down the tree as needed. However,
 * this is not ideal: if the total number of filters across all tasks is large,
 * we'll need a large number of fds. The assumption here is that the number of
 * filters (note: multiple tasks can point to the same filter) is small since
 * most sandboxes probably have at most one or two policies installed.
 */
int prepare_seccomp_filters(void)
{
	struct cr_img *img;

	img = open_image(CR_FD_SECCOMP, O_RSTR);
	if (!img)
		return 0; /* there were no filters */

	ret = pb_read_one_eof(img, &se, PB_SECCOMP);
	close_image(img);
	if (ret < 0)
		return -1;

	BUG_ON(!se);

	return 0;
}

int collect_seccomp_filters(void)
{
	current->
out:
	seccomp_entry__free_unpacked(se, NULL);
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
