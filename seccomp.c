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
#include "rst-malloc.h"

#include "protobuf.h"
#include "protobuf/seccomp.pb-c.h"

/* populated on dump during collect_seccomp_filters() */
static int next_filter_id = 0;

static struct seccomp_info *find_inherited(struct pstree_item *parent,
					   struct sock_filter *filter, int len)
{
	struct seccomp_info *info = dmpi(parent)->pi_creds->last_filter;

	for (info = dmpi(parent)->pi_creds->last_filter; info; info = info->prev) {

		if (len != info->filter.filter.len)
			continue;
		if (!memcmp(filter, info->filter.filter.data, len))
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
		struct seccomp_info *info, *inherited = NULL;

		len = ptrace(PTRACE_SECCOMP_GET_FILTER, item->pid.real, i, buf);
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

			goto save_infos;
		}

		info = xmalloc(sizeof(*info));
		if (!info)
			goto out;
		seccomp_filter__init(&info->filter);

		info->filter.filter.len = len;
		info->filter.filter.data = xmalloc(info->filter.filter.len);
		if (!info->filter.filter.data)
			goto out;

		memcpy(info->filter.filter.data, buf, info->filter.filter.len);

		info->prev = infos;
		infos = info;
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
		xfree(freeme->filter.filter.data);
		xfree(freeme);
	}

	return ret;
}

static int dump_seccomp_filters(void)
{
	struct pstree_item *item;
	SeccompEntry se = SECCOMP_ENTRY__INIT;
	int ret = -1;

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
			se.seccomp_filters[cursor->id] = &cursor->filter;

			/* these filters were already dumped */
			if (ret > 0)
				break;
		}
	}

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SECCOMP), &se, PB_SECCOMP);

	xfree(se.seccomp_filters);

/* XXX: we need a way to free each seccomp_info, or mark it freed here or something.
	for_each_pstree_item(item) {
		struct seccomp_info *cursor;

		cursor = dmpi(item)->pi_creds->last_filter;

		while (cursor) {
			struct seccomp_info *freeme = cursor;
			cursor = cursor->prev;

			xfree(freeme->filter.filter.data);
			xfree(freeme);
		}
	}
*/

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
	int ret;

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

int seccomp_filters_get_rst_pos(CoreEntry *core, int *count, unsigned long *pos)
{
	SeccompFilter *sf = NULL;
	struct sock_fprog *arr = NULL;
	int ret = -1, i;

	if (!core->tc->has_seccomp_filter) {
		*count = 0;
		return 0;
	}

	*count = 0;
	*pos = rst_mem_cpos(RM_PRIVATE);

	BUG_ON(core->tc->seccomp_filter > se->n_seccomp_filters);
	sf = se->seccomp_filters[core->tc->seccomp_filter];

	while (1) {
		(*count)++;

		if (!sf->has_prev)
			break;

		sf = se->seccomp_filters[sf->prev];
	}

	arr = rst_mem_alloc(sizeof(*arr) * (*count), RM_PRIVATE);
	if (!arr)
		goto out;

	sf = se->seccomp_filters[core->tc->seccomp_filter];
	for (i = 0; i < *count; i++) {
		struct sock_fprog *fprog = &arr[i];
		// XXX: this is a bit fugly; is there a better way?
		unsigned long temp_pos = rst_mem_cpos(RM_PRIVATE);

		BUG_ON(sf->filter.len % sizeof(struct sock_filter));
		fprog->len = sf->filter.len / sizeof(struct sock_filter);

		fprog->filter = rst_mem_alloc(sf->filter.len, RM_PRIVATE);
		if (!fprog->filter)
			goto out;

		memcpy(fprog->filter, sf->filter.data, sf->filter.len);
		fprog->filter = (struct sock_filter *) temp_pos;

		sf = se->seccomp_filters[sf->prev];
	}

	ret = 0;

out:
	seccomp_entry__free_unpacked(se, NULL);
	return ret;
}
