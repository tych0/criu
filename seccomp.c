#include <linux/filter.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "imgset.h"
#include "kcmp.h"
#include "pstree.h"
#include "ptrace.h"
#include "proc_parse.h"
#include "seccomp.h"
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

		if (!sys_kcmp(pid, pid, KCMP_FILE_PRIVATE_DATA, filter, info->fd))
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
			/* end of the search */
			if (errno == EINVAL) {
				goto save_filters;
			} else
				goto out;
		}

		inherited = find_inherited(item->parent, fd);
		if (inherited) {
			/* if this is the first filter we inherited, we can
			 * close this FD and just refer to that filter chain
			 */
			close(fd);
			dmpi(item)->pi_creds->inherited = inherited;

			for (cursor = filters; cursor->prev; cursor = cursor->prev)
				;
			cursor->prev = inherited;
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
	int len, prev_id;
	cr_seccomp_fd fd;
	struct sock_filter insns[BPF_MAXINSNS];
	SeccompFilter *filter;

	if (filters[info->id])
		return 1;

	fd.size = sizeof(fd);
	fd.dump_fd = info->fd;
	fd.insns = insns;

	len = sys_seccomp(SECCOMP_FILTER_FD, SECCOMP_FD_DUMP, (char *) &fd);
	if (len < 0) {
		pr_perror("seccomp fd dump failed");
		return -1;
	}

	BUG_ON(len % sizeof(insns[0]));

	filter = filters[info->id] = xmalloc(sizeof(*filter));
	if (!filter)
		return -1;

	filter->id = info->id;

	prev_id = -1;
	if (info->prev)
		prev_id = info->prev->id;
	filter->prev = prev_id;

	filter->filter.len = len;
	filter->filter.data = xmalloc(len);
	if (!filter->filter.data) {
		xfree(filter);
		return -1;
	}

	memcpy(filter->filter.data, fd.insns, len);
	return 0;
}

static int dump_seccomp_filters(void)
{
	struct pstree_item *item;
	SeccompEntry se = SECCOMP_ENTRY__INIT;
	int ret = -1, i;

	se.seccomp_filters = xzalloc(sizeof(*se.seccomp_filters) * next_filter_id);
	if (!se.seccomp_filters)
		return -1;

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
static int *fds = NULL;
static int n_fds = 0;

/* For now, we open /all/ of the seccomp fds in the root task, and just inherit
 * them all (and close them all) further on down the tree as needed. However,
 * this is not ideal: if the total number of filters across all tasks is large,
 * we'll need a large number of fds. The assumption here is that the number of
 * filters (note: multiple tasks can point to the same filter) is small since
 * most sandboxes probably have at most one or two policies installed.
 */
int prepare_seccomp_filters(void)
{
	SeccompEntry *se;
	struct cr_img *img;
	int ret = -1, i;
	struct pstree_item *item;
	struct seccomp_fd fd;
	struct sock_fprog fprog;

	img = open_image(CR_FD_CGROUP, O_RSTR);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &se, PB_SECCOMP);
	close_image(img);
	if (ret < 0)
		return -1;

	fd.size = sizeof(fd);
	fd.new_prog = &fprog;

	for (i = 0; i < se->n_seccomp_filters; i++) {
		SeccompFilter *sf = se->seccomp_filters[i];

		fprog.len = sf->filter.len / sizeof(struct sock_filter);
		fprog.filter = (struct sock_filter *) sf->filter.data;

		fds[sf->id] = sys_seccomp(SECCOMP_FILTER_FD, SECCOMP_FD_NEW, (char *) &fd);
		if (fds[sf->id] < 0) {
			pr_perror("importing seccomp program failed");
			goto out;
		}
	}

	for_each_pstree_item(item) {
		struct rst_info *ri = rsti(item);

		for (i = ri->seccomp_filter; i >= 0; i = se->seccomp_filters[i]->prev) {
			void *m;

			m = realloc(ri->seccomp_fds, sizeof(*ri->seccomp_fds) * (ri->nr_seccomp_fds + 1));
			if (!m)
				goto out;

			ri->seccomp_fds = m;
			ri->seccomp_fds[ri->nr_seccomp_fds++] = fds[i];

			/* The last filter we should restore is the first
			 * inherited one, because we expect the process that
			 * didn't inherit this filter to correctly restore
			 * what's above it.
			 */
			if (ri->inherited == i)
				break;
		}
	}

	ret = 0;
out:
	if (ret < 0) {
		for (i = 0; i < n_fds; i++)
			close(fds[i]);
	}

	seccomp_entry__free_unpacked(se, NULL);
	return ret;
}

/* This closes any seccomp fds that aren't used by this task in preparation for
 * entry into the restorer blob (which isntalls the filters and then closes the
 * remaining fds).
 */
void close_unused_seccomp_filters(struct pstree_item *item)
{
	int i, j;
	struct rst_info *ri = rsti(item);

	BUG_ON(!fds);
	for (i = 0; i < n_fds; i++) {
		bool found = false;

		if (ri->seccomp_fds) {
			for (j = 0; j < ri->nr_seccomp_fds; i++) {
				if (fds[i] == ri->seccomp_fds[i]) {
					found = true;
					break;
				}
			}
		}

		if (!found)
			close_safe(&fds[i]);
	}

	xfree(fds);
}
