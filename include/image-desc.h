#ifndef __CR_IMAGE_DESC_H__
#define __CR_IMAGE_DESC_H__

#include "asm/int.h"

enum {
	CR_FD_INVENTORY,
	CR_FD_STATS,
	/*
	 * Task entries
	 */

	_CR_FD_TASK_FROM,
	CR_FD_CORE,
	CR_FD_IDS,
	CR_FD_MM,
	CR_FD_SIGACT,
	CR_FD_CREDS,
	CR_FD_FS,
	_CR_FD_TASK_TO,

	CR_FD_PAGEMAP,

	/*
	 * NS entries
	 */
	CR_FD_UTSNS,
	CR_FD_MNTS,
	CR_FD_USERNS,

	_CR_FD_IPCNS_FROM,
	CR_FD_IPC_VAR,
	CR_FD_IPCNS_SHM,
	CR_FD_IPCNS_MSG,
	CR_FD_IPCNS_SEM,
	_CR_FD_IPCNS_TO,

	_CR_FD_NETNS_FROM,
	CR_FD_NETDEV,
	CR_FD_IFADDR,
	CR_FD_ROUTE,
	CR_FD_ROUTE6,
	CR_FD_IPTABLES,
	CR_FD_NETNS,
	_CR_FD_NETNS_TO,

	CR_FD_PSTREE,
	CR_FD_SHMEM_PAGEMAP,
	CR_FD_GHOST_FILE,
	CR_FD_TCP_STREAM,
	CR_FD_FDINFO,

	_CR_FD_GLOB_FROM,
	CR_FD_SK_QUEUES,
	CR_FD_REG_FILES,
	CR_FD_EXT_FILES,
	CR_FD_NS_FILES,
	CR_FD_INETSK,
	CR_FD_UNIXSK,
	CR_FD_PACKETSK,
	CR_FD_NETLINK_SK,
	CR_FD_PIPES,
	CR_FD_PIPES_DATA,
	CR_FD_FIFO,
	CR_FD_FIFO_DATA,
	CR_FD_TTY_FILES,
	CR_FD_TTY_INFO,
	CR_FD_REMAP_FPATH,
	CR_FD_EVENTFD_FILE,
	CR_FD_EVENTPOLL_FILE,
	CR_FD_SIGNALFD,
	CR_FD_INOTIFY_FILE,
	CR_FD_FANOTIFY_FILE,
	CR_FD_TUNFILE,
	CR_FD_CGROUP,
	CR_FD_TIMERFD,
	CR_FD_FILE_LOCKS,
	CR_FD_SECCOMP,
	_CR_FD_GLOB_TO,

	CR_FD_TMPFS_IMG,
	CR_FD_TMPFS_DEV,
	CR_FD_PAGES,

	CR_FD_VMAS,
	CR_FD_PAGES_OLD,
	CR_FD_SHM_PAGES_OLD,
	CR_FD_RLIMIT,
	CR_FD_ITIMERS,
	CR_FD_POSIX_TIMERS,
	CR_FD_FILE_LOCKS_PID,

	CR_FD_IRMAP_CACHE,
	CR_FD_CPUINFO,

	CR_FD_SIGNAL,
	CR_FD_PSIGNAL,
	CR_FD_INOTIFY_WD,
	CR_FD_FANOTIFY_MARK,
	CR_FD_EVENTPOLL_TFD,

	CR_FD_MAX
};

/* file descriptors template */
struct cr_fd_desc_tmpl {
	const char	*fmt;			/* format for the name */
	u32		magic;			/* magic in the header */
	int		oflags;			/* flags for image_open */
};

extern struct cr_fd_desc_tmpl imgset_template[CR_FD_MAX];

#endif /* __CR_IMAGE_DESC_H__ */
