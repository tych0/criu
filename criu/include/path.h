#ifndef __CR_PATH_H__
#define __CR_PATH_H__

/* Asolute paths are used on dump and relative paths are used on restore */
static inline int is_root(char *p)
{
	return (!strcmp(p, "/"));
}

/* True for the root mount (the topmost one) */
static inline int is_root_mount(struct mount_info *mi)
{
	return is_root(mi->mountpoint + 1);
}

/*
 * True if the mountpoint target is root on its FS.
 *
 * This is used to determine whether we need to postpone
 * mounting. E.g. one can bind mount some subdir from a
 * disk, and in this case we'll have to get the root disk
 * mount first, then bind-mount it. See do_mount_one().
 */
static inline int fsroot_mounted(struct mount_info *mi)
{
	return is_root(mi->root);
}

char *cut_root_for_bind(char *target_root, char *source_root);

#endif
