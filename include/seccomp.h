#ifndef __CR_SECCOMP_H__
#define __CR_SECCOMP_H__

#include <linux/seccomp.h>

#ifndef SECCOMP_MODE_DISABLED
#define SECCOMP_MODE_DISABLED 0
#endif

#ifndef SECCOMP_MODE_STRICT
#define SECCOMP_MODE_STRICT 1
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

/* for the seccomp syscall */
#ifndef SECCOMP_MODE_FILTER_EBPF
#define SECCOMP_MODE_FILTER_EBPF	2

struct seccomp_ebpf {
	unsigned int size;

	union {
		/* SECCOMP_EBPF_ADD_FD */
		struct {
			unsigned int    add_flags;
			__u32           add_fd;
		};
	};
};

typedef struct seccomp_ebpf seccomp_restore_arg;
#else
typedef struct seccomp_ebpf seccomp_restore_arg;
#endif

#ifndef SECCOMP_EBPF_ADD_FD
#define SECCOMP_EBPF_ADD_FD	0
#endif

#endif
