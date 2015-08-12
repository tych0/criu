#ifndef __CR_BPF_H__
#define __CR_BPF_H__

#include <linux/unistd.h>
#include <linux/bpf.h>

#ifndef BPF_PROG_TYPE_SECCOMP
#define BPF_PROG_TYPE_SECCOMP 5
#endif

#ifndef BPF_PROG_LOAD
#define BPF_PROG_LOAD 5
#endif

#ifndef BPF_PROG_DUMP
#define BPF_PROG_DUMP 6

/*
 * The bpf syscall API uses a giant union of anonymous structs as its
 * interface; if we don't have BPF_PROG_DUMP, we also won't have the members
 * that are new for it. We define a struct here and use that instead.
*/
struct criu_bpf_dump {
                __u32		prog_fd;
                __u32		dump_insn_cnt;
                __aligned_u64	dump_insns;
                __u8		gpl_compatible;
		__u64		prog_id;
} __attribute__((aligned(8)));

typedef struct criu_bpf_dump bpf_dump_arg;
#else
typedef union bpf_attr bpf_dump_arg;
#endif /* BPF_PROG_DUMP */

#endif
