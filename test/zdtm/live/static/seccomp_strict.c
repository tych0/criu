#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/limits.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that SECCOMP_MODE_STRICT is restored";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

int main(int argc, char ** argv)
{
	pid_t pid;
	FILE *f;
	char buf[PATH_MAX];
	bool found = false;
	int ret = 1;

	test_init(argc, argv);

	pid = fork();
	if (pid < 0) {
		err("fork");
		return -1;
	}

	if (pid == 0) {
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) < 0) {
			err("prctl failed");
			return -1;
		}

		while(1)
			/* can't sleep() here, seccomp kills us */;
	}

	test_daemon();
	test_waitsig();

	sprintf(buf, "/proc/%d/status", pid);
	f = fopen(buf, "r+");
	if (!f) {
		err("fopen failed");
		goto out;
	}

	while (NULL != fgets(buf, sizeof(buf), f)) {
		int mode;
		char state;

		if (sscanf(buf, "State: %c %*s", &state) == 1 && state != 'R') {
			fail("resumed but state is not R (%c), seccomp killed the process during resume\n", state);
			goto out;
		}

		if (sscanf(buf, "Seccomp:\t%d", &mode) != 1)
			continue;

		found = true;
		if (mode != SECCOMP_MODE_STRICT) {
			fail("seccomp mode mismatch %d\n", mode);
			fclose(f);
			goto out;
		}

		break;
	}
	fclose(f);

	if (!found) {
		fail("seccomp not found?\n");
		goto out;
	}

	ret = 0;
	pass();
out:
	kill(pid, SIGKILL);
	return ret;
}
