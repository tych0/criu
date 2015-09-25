#ifndef __CR_SECCOMP_H__
#define __CR_SECCOMP_H__

#include <linux/seccomp.h>
#include <linux/filter.h>

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
#ifndef SECCOMP_FILTER_FD
#define SECCOMP_FILTER_FD	2

#define SECCOMP_FD_NEW		0
#define SECCOMP_FD_INSTALL	1
#define	SECCOMP_FD_DUMP	2

struct seccomp_fd {
	unsigned int size;

	union {
		/* SECCOMP_FD_NEW */
		struct sock_fprog	*new_prog;

		/* SECCOMP_FD_INSTALL */
		int			install_fd;

		/* SECCOMP_FD_DUMP */
		struct {
			int			dump_fd;
			struct sock_filter	*insns;
		};
	};
};

typedef struct seccomp_fd cr_seccomp_fd;
#else
typedef struct seccomp_fd cr_seccomp_fd;
#endif

struct pstree_item *item;

extern int collect_seccomp_filters(void);
extern int prepare_seccomp_filters(void);
extern int fill_seccomp_fds(struct pstree_item *item);
extern void close_unused_seccomp_filters(struct pstree_item *item);
#endif
