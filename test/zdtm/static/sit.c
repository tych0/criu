#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sched.h>
#include "zdtmtst.h"

const char *test_doc	= "check that empty bridges are c/r'd correctly";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

#define SIT_NAME "zdtmsit"

int add_sit(void)
{
	if (system("ip tunnel add " SIT_NAME " mode sit local 1.2.3.4 remote 4.5.6.7")) {
		pr_perror("tunnel create failed");
		return -1;
	}

	return 0;
}

void del_bridge(void)
{
	if (system("ip tunnel del " SIT_NAME))
		pr_perror("tunnel delete failed");
}

int main(int argc, char **argv)
{
	int ret = -1;

	unshare(CLONE_NEWNET);

	test_init(argc, argv);

	if (add_sit())
		return 1;

	if (system("ip tunnel list | grep " SIT_NAME " > sit.dump.test")) {
		fail("can't save tunnel config");
		goto out;
	}

	test_daemon();
	test_waitsig();

	errno = 0;
	if (system("ip tunnel list | grep " SIT_NAME " > sit.rst.test")) {
		fail("can't save tunnel config");
		goto out;
	}

	if (system("diff sit.rst.test sit.dump.test")) {
		fail("Net config differs after restore");
		goto out;
	}

	pass();
	ret = 0;

out:
	del_bridge();
	return ret;
}
