#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif

const char *test_doc	= "Test a not-really-external external mount";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

int main(int argc, char ** argv)
{
	/*
	 * The magic here happens in zdtm.sh, which unshares before it invokes
	 * the test so that criu incorrectly matches external mounts.
	 */
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();

	return 0;

	/*
	char src[PATH_MAX], *root;
	int status;
	pid_t pid;

	root = getenv("ZDTM_ROOT");
	if (root == NULL) {
		err("root");
		return 1;
	}

	if (strcmp(getenv("ZDTM_NEWNS"), "1"))
		goto test;

	sprintf(src, "%s/src", root);

	mkdir(src, 0700);

	if (mount(NULL, src, "tmpfs", 0, NULL)) {
		err("mount");
		return 1;
	}

	pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		pid_t pid2;
		test_ext_init(argc, argv);
		pid2 = fork();
		if (pid2 < 0) {
			err("fork2");
			return 1;
		}

		if (pid2 == 0) {
			unshare(CLONE_NEWNS);
			return 1;
		}

		wait(NULL);

		return 0;
	}

	wait(&status);
	if (status != 0)
		return 1;

test:
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();

	return 0;
	*/
}
