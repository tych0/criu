#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#ifdef __NR_seccomp
#include <linux/seccomp.h>
#include <linux/filter.h>
#endif

#ifndef SECCOMP_FILTER_FLAG_LOG
#define SECCOMP_FILTER_FLAG_LOG 2
#endif

#ifndef PTRACE_SECCOMP_GET_METADATA
#define PTRACE_SECCOMP_GET_METADATA 0x420d
struct seccomp_metadata {
	unsigned long filter_off;
	unsigned int flags;
};
#endif

#include "zdtmtst.h"

const char *test_doc	= "Check that SECCOMP_MODE_FILTER is restored";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

#ifdef __NR_seccomp

bool supports_log;

static int get_seccomp_mode(pid_t pid)
{
	FILE *f;
	char buf[PATH_MAX];

	sprintf(buf, "/proc/%d/status", pid);
	f = fopen(buf, "r+");
	if (!f) {
		pr_perror("fopen failed");
		return -1;
	}

	while (NULL != fgets(buf, sizeof(buf), f)) {
		int mode;

		if (sscanf(buf, "Seccomp:\t%d", &mode) != 1)
			continue;

		fclose(f);
		return mode;
	}
	fclose(f);

	return -1;
}

static bool check_log_set(pid_t pid)
{
	bool ret = false;
	struct seccomp_metadata md = { .filter_off = 0 };

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		pr_perror("ptrace attach");
		return false;
	}

	waitpid(pid, NULL, 0);

	if (ptrace(PTRACE_SECCOMP_GET_METADATA, pid, sizeof(md), &md) < 0) {
		if (!(errno == EIO && supports_log))
			pr_perror("get flags failed");
		else
			ret = true;
	} else if (!(md.flags & SECCOMP_FILTER_FLAG_LOG)) {
		pr_err("bad flag bit\n");
	} else {
		test_msg("good flag bit\n");
		ret = true;
	}

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
		pr_perror("ptrace detach");

	return ret;
}

int filter_syscall(int syscall_nr)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall_nr, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog bpf_prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	unsigned long flags = 0;

	if (supports_log)
		flags |= SECCOMP_FILTER_FLAG_LOG;

	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, flags, &bpf_prog) < 0) {
		pr_perror("prctl failed");
		return -1;
	}

	return 0;
}

static bool test_for_log_flag(void)
{
	pid_t pid;
	int status;

	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ptrace, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog bpf_prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	/* We have to fork to do this test, because the check for
	 * PTRACE_SECCOMP_GET_METADATA checks whether or not we're under the
	 * influence of a seccomp filter, so we need a throwaway process to
	 * check for -EINVAL.
	 */
	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return false;
	}

	if (!pid) {
		if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, &bpf_prog) < 0) {
			pr_perror("seccomp");
			exit(1);
		}

		exit(0);
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		return false;
	}

	return WIFEXITED(status) && !WEXITSTATUS(status);
}

int main(int argc, char ** argv)
{
	pid_t pid;
	int mode, status;
	int sk_pair[2], sk, ret;
	char c = 'K';

	supports_log = test_for_log_flag();

	test_init(argc, argv);

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair)) {
		pr_perror("socketpair");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return -1;
	}

	if (pid == 0) {

		sk = sk_pair[1];
		close(sk_pair[0]);

		/*
		 * Let's install a few filters separately to make sure the
		 * chaining actually works.
		 */
		if (filter_syscall(__NR_ptrace) < 0)
			_exit(1);

		/*
		 * The idea is to have a syscall that is used in restore_creds,
		 * so we can make sure seccomp is actually suspended when that
		 * is called.
		 */
		if (filter_syscall(__NR_setresuid) < 0)
			_exit(1);

		setuid(1000);

		zdtm_seccomp = 1;
		test_msg("SECCOMP_MODE_FILTER is enabled\n");

		if (write(sk, &c, 1) != 1) {
			pr_perror("write");
			_exit(1);
		}

		if (read(sk, &c, 1) != 1) {
			pr_perror("read");
			_exit(1);
		}

		prctl(PR_SET_DUMPABLE, 1);

		if (write(sk, &c, 1) != 1) {
			pr_perror("write");
			_exit(1);
		}

		if (read(sk, &c, 1) != 1) {
			pr_perror("read");
			_exit(1);
		}

		/* We expect to be killed by our policy above. */
		ptrace(PTRACE_TRACEME);

		syscall(__NR_exit, 0);
	}

	sk = sk_pair[0];
	close(sk_pair[1]);

	if ((ret = read(sk, &c, 1)) != 1) {
		pr_perror("read %d", ret);
		goto err;
	}

	test_daemon();
	test_waitsig();

	/* This ptracing is -EPERM'd in the uns case, so let's ignore it. */
	if (supports_log && !check_log_set(pid) && getenv("ZDTM_NEWNS")) {
		pr_err("log not set?\n");
		goto err;
	}

	if (write(sk, &c, 1) != 1) {
		pr_perror("write");
		goto err;
	}
	if ((ret = read(sk, &c, 1)) != 1) {
		pr_perror("read %d", ret);
		goto err;
	}

	mode = get_seccomp_mode(pid);
	if (write(sk, &c, 1) != 1) {
		pr_perror("write");
		goto err;
	}
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		exit(1);
	}

	if (WTERMSIG(status) != SIGSYS) {
		pr_perror("expected SIGSYS, got %d", WTERMSIG(status));
		exit(1);
	}

	if (mode != SECCOMP_MODE_FILTER) {
		fail("seccomp mode mismatch %d\n", mode);
		return 1;
	}

	pass();

	return 0;
err:
	kill(pid, SIGKILL);
	return 1;
}

#else /* __NR_seccomp */

#define TEST_SKIP_REASON "incompatible kernel (no seccomp)"
#include "skip-me.c"

#endif /* __NR_seccomp */
