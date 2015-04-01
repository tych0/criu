#define _GNU_SOURCE
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <syscall.h>

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif

const char *test_doc	= "Check that external shard mounts work.";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "external master name", 1);

static int pivot_root(const char *new_root, const char *put_old)
{
#ifdef __NR_pivot_root
return syscall(__NR_pivot_root, new_root, put_old);
#else
errno = ENOSYS;
return -1;
#endif
}

static int setup_rootfs_pivot_root(const char *rootfs)
{
	int oldroot = -1, newroot = -1;

	oldroot = open("/", O_DIRECTORY | O_RDONLY);
	if (oldroot < 0) {
		err("Error opening old-/ for fchdir");
		return -1;
	}
	newroot = open(rootfs, O_DIRECTORY | O_RDONLY);
	if (newroot < 0) {
		err("Error opening new-/ for fchdir");
		goto fail;
	}

	/* change into new root fs */
	if (fchdir(newroot)) {
		err("can't chdir to new rootfs '%s'", rootfs);
		goto fail;
	}

	/* pivot_root into our new root fs */
	if (pivot_root(".", "oldroot")) {
		err("pivot_root syscall failed");
		goto fail;
	}

	/*
	 * at this point the old-root is mounted on top of our new-root
	 * To unmounted it we must not be chdir'd into it, so escape back
	 * to old-root
	 */
	if (fchdir(oldroot) < 0) {
		err("Error entering oldroot");
		goto fail;
	}
	if (umount2(".", MNT_DETACH) < 0) {
		err("Error detaching old root");
		goto fail;
	}

	if (fchdir(newroot) < 0) {
		err("Error re-entering newroot");
		goto fail;
	}

	close(oldroot);
	close(newroot);

	test_msg("pivot_root syscall to '%s' successful\n", rootfs);

	return 0;

fail:
	if (oldroot != -1)
		close(oldroot);
	if (newroot != -1)
		close(newroot);
	return -1;
}

int main(int argc, char **argv)
{
	int ret = 1;
	FILE *f;
	char buf[PATH_MAX], root_dir[PATH_MAX], source[PATH_MAX], bind[PATH_MAX];

	test_init(argc, argv);

	sprintf(root_dir, "%s/root", dirname);
	sprintf(source, "%s/source", dirname);
	sprintf(bind, "%s/bind", root_dir);

	if (mkdir(dirname, 0700) < 0) {
		err("can't make dir");
		goto out;
	}

	if (mkdir(root_dir, 0700) < 0) {
		err("can't make dir");
		goto out;
	}

	if (mkdir(source, 0700) < 0) {
		err("can't make dir");
		goto out;
	}

	if (mkdir(bind, 0700) < 0) {
		err("can't make dir");
		goto out;
	}

	// touch a file to test
	sprintf(buf, "%s/foo", source);
	f = fopen(buf, "w");
	if (!f) {
		err("can't open foo");
		goto out;
	}
	fclose(f);

	if (unshare(CLONE_NEWNS)) {
		err("can't unshare");
		goto out;
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		err("can't mount");
		goto out;
	}

	if (mount(source, bind, "none", MS_BIND, NULL)) {
		err("can't mount");
		goto umount;
	}

	if (mount(NULL, bind, NULL, MS_SHARED, NULL)) {
		err("can't set shared");
		goto umount;
	}

	if (mount(NULL, bind, NULL, MS_SLAVE, NULL)) {
		err("can't set slave");
		goto umount;
	}

	if (mount(root_dir, root_dir, "none", MS_BIND, NULL)) {
		err ("can't mount");
		goto umount;
	}
	system("cat /proc/self/mountinfo");

	sprintf(buf, "%s/oldroot", root_dir);
	mkdir(buf, 0700);

	if (setup_rootfs_pivot_root(root_dir) < 0) {
		err("can't pivot_root");
		goto umount;
	}

	test_daemon();
	test_waitsig();

	if (access("/foo", F_OK) < 0) {
		fail("can't see foo");
		goto out;
	}

	pass();
	return 0;
umount:
	umount(bind);
	rmdir(dirname);
out:
	return ret;
}
