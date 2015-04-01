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

int main(int argc, char **argv)
{
	int ret = 1;
	FILE *f;
	char buf[PATH_MAX], bind1[PATH_MAX], bind2[PATH_MAX], bind3[PATH_MAX];

	test_init(argc, argv);

	sprintf(bind1, "%s/bind1", dirname);
	sprintf(bind2, "%s/bind2", dirname);
	sprintf(bind3, "%s/bind3", dirname);

	if (mkdir(dirname, 0700) < 0) {
		err("can't make dir");
		goto out;
	}

	if (mkdir(bind1, 0700) < 0) {
		err("can't make dir");
		goto out;
	}

	if (mkdir(bind2, 0700) < 0) {
		err("can't make dir");
		goto out;
	}

	if (mkdir(bind3, 0700) < 0) {
		err("can't make dir");
		goto out;
	}

	// touch a file to test
	sprintf(buf, "%s/foo", bind1);
	f = fopen(buf, "w");
	if (!f) {
		err("can't open foo");
		goto out;
	}
	fclose(f);

	/*
	 * We want something like:
	 *
	 * mount --bind bind1 bind2
	 * mount --make-private bind2
	 * mount --make-shared bind2
	 * mount --bind bind2 bind3
	 * mount --make-shared bind3
	 * mount --make-slave bind3
	 * unshare -m
	 * mount --make-private bind2
	 * umount bind2
	 * c/r
	 */

	if (mount(bind1, bind2, NULL, MS_BIND, NULL)) {
		err("can't mount");
		goto umount;
	}

	/* toggle private so we get our own sharing if rootfs is shared */
	if (mount(NULL, bind2, NULL, MS_PRIVATE, NULL)) {
		err("can't set private");
		goto umount;
	}

	if (mount(NULL, bind2, NULL, MS_SHARED, NULL)) {
		err("can't set shared");
		goto umount;
	}

	if (mount(bind2, bind3, NULL, MS_BIND, NULL)) {
		err("can't mount bind2 to bind3");
		goto umount;
	}

	if (mount(NULL, bind3, NULL, MS_SLAVE, NULL)) {
		err("can't set slave");
		goto umount;
	}

	if (unshare(CLONE_NEWNS)) {
		err("can't do second unshare");
		goto umount;
	}

	if (mount(NULL, bind2, NULL, MS_PRIVATE, NULL)) {
		err("can't set private");
		goto umount;
	}

	if (umount(bind2)) {
		err("can't umount");
		goto umount;
	}

	/* bind3 is now master:n with no bind2 in the current namespace.
	 * In the parent namespace bind2 is shared:n */

	test_daemon();
	test_waitsig();

	sprintf(buf, "%s/foo", bind3);
	if (access("/foo", F_OK) < 0) {
		fail("can't see foo");
		goto out;
	}

	pass();
	return 0;

umount:
	umount(bind2);
	umount(bind3);
	rmdir(dirname);
out:
	return ret;
}
