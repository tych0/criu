#ifndef __CR_CGROUP_H__
#define __CR_CGROUP_H__
#include "asm/int.h"
#include "list.h"
struct pstree_item;
extern u32 root_cg_set;
int dump_task_cgroup(struct pstree_item *, u32 *);
int dump_cgroups(void);
int prepare_task_cgroup(struct pstree_item *);
int prepare_cgroup(void);
void fini_cgroup(void);

#define HAS_MEM_LIMIT	(1 << 0)
#define HAS_CPU_SHARES	(1 << 1)

struct cg_controller;

struct cgroup_dir {
	char			*path;
	u64			mem_limit;
	u32			cpu_shares;
	unsigned int		flags;

	/* this is how children are linked together */
	struct list_head	siblings;

	/* more cgroup_dirs */
	struct list_head	children;
	unsigned int		n_children;

	struct cg_controller	*controller;
};

struct cg_controller {
	unsigned int		heirarchy;
	unsigned int		n_controllers;
	char			**controllers;

	/* cgroup_dirs */
	struct list_head 	heads;
	unsigned int		n_heads;

	/* for cgroup list in cgroup.c */
	struct list_head	l;
};

/* Parse /proc/cgroups for co-mounted cgroups and initialize internal
 * structures. */
int parse_cgroups();

#endif /* __CR_CGROUP_H__ */
