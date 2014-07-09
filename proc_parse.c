#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <linux/fs.h>

#include "asm/types.h"
#include "list.h"
#include "util.h"
#include "mount.h"
#include "mman.h"
#include "cpu.h"
#include "file-lock.h"
#include "pstree.h"
#include "fsnotify.h"
#include "posix-timer.h"
#include "kerndat.h"
#include "vdso.h"
#include "vma.h"

#include "proc_parse.h"
#include "protobuf.h"
#include "protobuf/fdinfo.pb-c.h"

#include <stdlib.h>

struct buffer {
	char buf[PAGE_SIZE];
	char end; /* '\0' */
};

static struct buffer __buf;
static char *buf = __buf.buf;

#define BUF_SIZE sizeof(__buf.buf)

int parse_cpuinfo_features(int (*handler)(char *tok))
{
	FILE *cpuinfo;

	cpuinfo = fopen("/proc/cpuinfo", "r");
	if (!cpuinfo) {
		pr_perror("Can't open cpuinfo file");
		return -1;
	}

	while (fgets(buf, BUF_SIZE, cpuinfo)) {
		char *tok;

		if (strncmp(buf, "flags\t\t:", 8))
			continue;

		for (tok = strtok(buf, " \t\n"); tok;
		     tok = strtok(NULL, " \t\n")) {
			if (handler(tok) < 0)
				break;
		}
	}

	fclose(cpuinfo);
	return 0;
}

/* check the @line starts with "%lx-%lx" format */
static bool is_vma_range_fmt(char *line)
{
#define ____is_vma_addr_char(__c)		\
	(((__c) <= '9' && (__c) >= '0') ||	\
	((__c) <= 'f' && (__c) >= 'a'))

	while (*line && ____is_vma_addr_char(*line))
		line++;

	if (*line++ != '-')
		return false;

	while (*line && ____is_vma_addr_char(*line))
		line++;

	if (*line++ != ' ')
		return false;

	return true;
#undef ____is_vma_addr_char
}

static int parse_vmflags(char *buf, struct vma_area *vma_area)
{
	char *tok;
	bool shared = false;
	bool maywrite = false;

	if (!buf[0])
		return 0;

	tok = strtok(buf, " \n");
	if (!tok)
		return 0;

#define _vmflag_match(_t, _s) (_t[0] == _s[0] && _t[1] == _s[1])

	do {
		/* open() block */
		if (_vmflag_match(tok, "sh"))
			shared = true;
		else if (_vmflag_match(tok, "mw"))
			maywrite = true;

		/* mmap() block */
		if (_vmflag_match(tok, "gd"))
			vma_area->e->flags |= MAP_GROWSDOWN;
		else if (_vmflag_match(tok, "lo"))
			vma_area->e->flags |= MAP_LOCKED;
		else if (_vmflag_match(tok, "nr"))
			vma_area->e->flags |= MAP_NORESERVE;
		else if (_vmflag_match(tok, "ht"))
			vma_area->e->flags |= MAP_HUGETLB;

		/* madvise() block */
		if (_vmflag_match(tok, "sr"))
			vma_area->e->madv |= (1ul << MADV_SEQUENTIAL);
		else if (_vmflag_match(tok, "rr"))
			vma_area->e->madv |= (1ul << MADV_RANDOM);
		else if (_vmflag_match(tok, "dc"))
			vma_area->e->madv |= (1ul << MADV_DONTFORK);
		else if (_vmflag_match(tok, "dd"))
			vma_area->e->madv |= (1ul << MADV_DONTDUMP);
		else if (_vmflag_match(tok, "mg"))
			vma_area->e->madv |= (1ul << MADV_MERGEABLE);
		else if (_vmflag_match(tok, "hg"))
			vma_area->e->madv |= (1ul << MADV_HUGEPAGE);
		else if (_vmflag_match(tok, "nh"))
			vma_area->e->madv |= (1ul << MADV_NOHUGEPAGE);

		/* vmsplice doesn't work for VM_IO and VM_PFNMAP mappings. */
		if (_vmflag_match(tok, "io") || _vmflag_match(tok, "pf")) {
#ifdef CONFIG_VDSO
			/*
			 * VVAR area mapped by the kernel as
			 * VM_IO | VM_PFNMAP| VM_DONTEXPAND | VM_DONTDUMP
			 */
			if (!vma_area_is(vma_area, VMA_AREA_VVAR))
#endif
				vma_area->e->status |= VMA_UNSUPP;
		}

		/*
		 * Anything else is just ignored.
		 */
	} while ((tok = strtok(NULL, " \n")));

#undef _vmflag_match

	if (shared && maywrite)
		vma_area->e->fdflags = O_RDWR;
	else
		vma_area->e->fdflags = O_RDONLY;
	vma_area->e->has_fdflags = true;

	if (vma_area->e->madv)
		vma_area->e->has_madv = true;

	return 0;
}

static inline int is_anon_shmem_map(dev_t dev)
{
	return kerndat_shmem_dev == dev;
}

struct vma_file_info {
	int dev_maj;
	int dev_min;
	unsigned long ino;
	struct vma_area *vma;
};

static inline int vfi_equal(struct vma_file_info *a, struct vma_file_info *b)
{
	return ((a->ino ^ b->ino) |
			(a->dev_maj ^ b->dev_maj) |
			(a->dev_min ^ b->dev_min)) == 0;
}

static int vma_get_mapfile(struct vma_area *vma, DIR *mfd,
		struct vma_file_info *vfi, struct vma_file_info *prev_vfi)
{
	char path[32];

	if (!mfd)
		return 0;

	if (prev_vfi->vma && vfi_equal(vfi, prev_vfi)) {
		struct vma_area *prev = prev_vfi->vma;

		/*
		 * If vfi is equal (!) and negative @vm_file_fd --
		 * we have nothing to borrow for sure.
		 */
		if (prev->vm_file_fd < 0)
			return 0;

		pr_debug("vma %"PRIx64" borrows vfi from previous %"PRIx64"\n",
				vma->e->start, prev->e->start);
		vma->vm_file_fd = prev->vm_file_fd;
		if (prev->e->status & VMA_AREA_SOCKET)
			vma->e->status |= VMA_AREA_SOCKET | VMA_AREA_REGULAR;
		vma->file_borrowed = true;

		return 0;
	}

	/* Figure out if it's file mapping */
	snprintf(path, sizeof(path), "%"PRIx64"-%"PRIx64, vma->e->start, vma->e->end);

	/*
	 * Note that we "open" it in dumper process space
	 * so later we might refer to it via /proc/self/fd/vm_file_fd
	 * if needed.
	 */
	vma->vm_file_fd = openat(dirfd(mfd), path, O_RDONLY);
	if (vma->vm_file_fd < 0) {
		if (errno == ENXIO) {
			struct stat buf;

			if (fstatat(dirfd(mfd), path, &buf, 0))
				return -1;

			if (!S_ISSOCK(buf.st_mode))
				return -1;

			pr_info("Found socket %"PRIu64" mapping @%"PRIx64"\n",
					buf.st_ino, vma->e->start);
			vma->e->status |= VMA_AREA_SOCKET | VMA_AREA_REGULAR;
			vma->vm_socket_id = buf.st_ino;
		} else if (errno != ENOENT)
			return -1;
	}

	return 0;
}

int parse_self_maps_lite(struct vm_area_list *vms)
{
	FILE *maps;

	vm_area_list_init(vms);

	maps = fopen_proc(PROC_SELF, "maps");
	if (maps == NULL) {
		pr_perror("Can't open self maps");
		return -1;
	}

	while (fgets(buf, BUF_SIZE, maps) != NULL) {
		struct vma_area *vma;
		char *end;

		vma = alloc_vma_area();
		if (!vma) {
			fclose(maps);
			return -1;
		}

		vma->e->start = strtoul(buf, &end, 16);
		vma->e->end = strtoul(end + 1, NULL, 16);
		list_add_tail(&vma->list, &vms->h);
		vms->nr++;

		pr_debug("Parsed %"PRIx64"-%"PRIx64" vma\n", vma->e->start, vma->e->end);
	}

	fclose(maps);
	return 0;
}

static char smaps_buf[PAGE_SIZE];

int parse_smaps(pid_t pid, struct vm_area_list *vma_area_list, bool use_map_files)
{
	struct vma_area *vma_area = NULL;
	unsigned long start, end, pgoff, prev_end = 0;
	char r, w, x, s;
	int ret = -1;
	struct vma_file_info vfi;
	struct vma_file_info prev_vfi = {};

	DIR *map_files_dir = NULL;
	FILE *smaps = NULL;

	vma_area_list->nr = 0;
	vma_area_list->longest = 0;
	vma_area_list->priv_size = 0;
	INIT_LIST_HEAD(&vma_area_list->h);

	smaps = fopen_proc(pid, "smaps");
	if (!smaps)
		goto err;

	setvbuf(smaps, smaps_buf, _IOFBF, sizeof(smaps_buf));

	if (use_map_files) {
		map_files_dir = opendir_proc(pid, "map_files");
		if (!map_files_dir) /* old kernel? */
			goto err;
	}

	while (1) {
		int num;
		char file_path[6];
		bool eof;

		eof = (fgets(buf, BUF_SIZE, smaps) == NULL);

		if (!eof && !is_vma_range_fmt(buf)) {
			if (!strncmp(buf, "Nonlinear", 9)) {
				BUG_ON(!vma_area);
				pr_err("Nonlinear mapping found %016"PRIx64"-%016"PRIx64"\n",
				       vma_area->e->start, vma_area->e->end);
				/*
				 * VMA is already on list and will be
				 * freed later as list get destroyed.
				 */
				vma_area = NULL;
				goto err;
			} else if (!strncmp(buf, "VmFlags: ", 9)) {
				BUG_ON(!vma_area);
				if (parse_vmflags(&buf[9], vma_area))
					goto err;
				continue;
			} else
				continue;
		}

		if (vma_area) {
			if (vma_area->e->status & VMA_UNSUPP) {
				pr_err("Unsupported mapping found %016"PRIx64"-%016"PRIx64"\n",
							vma_area->e->start, vma_area->e->end);
				goto err;
			}

			/* Add a guard page only if here is enough space for it */
			if ((vma_area->e->flags & MAP_GROWSDOWN) &&
			    prev_end < vma_area->e->start)
				vma_area->e->start -= PAGE_SIZE; /* Guard page */
			prev_end = vma_area->e->end;

			list_add_tail(&vma_area->list, &vma_area_list->h);
			vma_area_list->nr++;
			if (privately_dump_vma(vma_area)) {
				unsigned long pages;

				pages = vma_area_len(vma_area) / PAGE_SIZE;
				vma_area_list->priv_size += pages;
				vma_area_list->longest = max(vma_area_list->longest, pages);
			}

			prev_vfi = vfi;
			prev_vfi.vma = vma_area;
		}

		if (eof)
			break;

		vma_area = alloc_vma_area();
		if (!vma_area)
			goto err;

		memset(file_path, 0, 6);
		num = sscanf(buf, "%lx-%lx %c%c%c%c %lx %x:%x %lu %5s",
			     &start, &end, &r, &w, &x, &s, &pgoff,
			     &vfi.dev_maj, &vfi.dev_min, &vfi.ino, file_path);
		if (num < 10) {
			pr_err("Can't parse: %s\n", buf);
			goto err;
		}

		vma_area->e->start	= start;
		vma_area->e->end	= end;
		vma_area->e->pgoff	= pgoff;
		vma_area->e->prot	= PROT_NONE;

		if (vma_get_mapfile(vma_area, map_files_dir, &vfi, &prev_vfi))
			goto err_bogus_mapfile;

		if (r == 'r')
			vma_area->e->prot |= PROT_READ;
		if (w == 'w')
			vma_area->e->prot |= PROT_WRITE;
		if (x == 'x')
			vma_area->e->prot |= PROT_EXEC;

		if (s == 's')
			vma_area->e->flags = MAP_SHARED;
		else if (s == 'p')
			vma_area->e->flags = MAP_PRIVATE;
		else {
			pr_err("Unexpected VMA met (%c)\n", s);
			goto err;
		}

		if (vma_area->e->status != 0) {
			continue;
		} else if (strstr(buf, "[vsyscall]") || strstr(buf, "[vectors]")) {
			vma_area->e->status |= VMA_AREA_VSYSCALL;
		} else if (strstr(buf, "[vdso]")) {
#ifdef CONFIG_VDSO
			vma_area->e->status |= VMA_AREA_REGULAR;
			if ((vma_area->e->prot & VDSO_PROT) == VDSO_PROT)
				vma_area->e->status |= VMA_AREA_VDSO;
#else
			pr_warn_once("Found vDSO area without support\n");
			goto err;
#endif
		} else if (strstr(buf, "[vvar]")) {
#ifdef CONFIG_VDSO
			vma_area->e->status |= VMA_AREA_REGULAR;
			if ((vma_area->e->prot & VVAR_PROT) == VVAR_PROT)
				vma_area->e->status |= VMA_AREA_VVAR;
#else
			pr_warn_once("Found VVAR area without support\n");
			goto err;
#endif
		} else if (strstr(buf, "[heap]")) {
			vma_area->e->status |= VMA_AREA_REGULAR | VMA_AREA_HEAP;
		} else {
			vma_area->e->status = VMA_AREA_REGULAR;
		}

		/*
		 * Some mapping hints for restore, we save this on
		 * disk and restore might need to analyze it.
		 */
		if (vma_area->file_borrowed) {
			struct vma_area *prev = prev_vfi.vma;

			/*
			 * Pick-up flags that might be set in the branch below.
			 * Status is copied as-is as it should be zero here,
			 * and have full match with the previous.
			 */
			vma_area->e->flags |= (prev->e->flags & MAP_ANONYMOUS);
			vma_area->e->status = prev->e->status;
			vma_area->e->shmid = prev->e->shmid;
			vma_area->st = prev->st;
		} else if (vma_area->vm_file_fd >= 0) {
			struct stat *st_buf;

			st_buf = vma_area->st = xmalloc(sizeof(*st_buf));
			if (!st_buf)
				goto err;

			if (fstat(vma_area->vm_file_fd, st_buf) < 0) {
				pr_perror("Failed fstat on %d's map %lu", pid, start);
				goto err;
			}

			if (!S_ISREG(st_buf->st_mode) &&
			    !(S_ISCHR(st_buf->st_mode) && st_buf->st_rdev == DEVZERO)) {
				pr_err("Can't handle non-regular mapping on %d's map %lu\n", pid, start);
				goto err;
			}

			/*
			 * /dev/zero stands for anon-shared mapping
			 * otherwise it's some file mapping.
			 */
			if (is_anon_shmem_map(st_buf->st_dev)) {
				if (!(vma_area->e->flags & MAP_SHARED))
					goto err_bogus_mapping;
				vma_area->e->flags  |= MAP_ANONYMOUS;
				vma_area->e->status |= VMA_ANON_SHARED;
				vma_area->e->shmid = st_buf->st_ino;

				if (!strcmp(file_path, "/SYSV")) {
					pr_info("path: %s\n", file_path);
					vma_area->e->status |= VMA_AREA_SYSVIPC;
				}
			} else {
				if (vma_area->e->flags & MAP_PRIVATE)
					vma_area->e->status |= VMA_FILE_PRIVATE;
				else
					vma_area->e->status |= VMA_FILE_SHARED;
			}
		} else {
			/*
			 * No file but mapping -- anonymous one.
			 */
			if (vma_area->e->flags & MAP_SHARED) {
				vma_area->e->status |= VMA_ANON_SHARED;
				vma_area->e->shmid = vfi.ino;
			} else {
				vma_area->e->status |= VMA_ANON_PRIVATE;
			}
			vma_area->e->flags  |= MAP_ANONYMOUS;
		}
	}

	vma_area = NULL;
	ret = 0;

err:
	if (smaps)
		fclose(smaps);

	if (map_files_dir)
		closedir(map_files_dir);

	xfree(vma_area);
	return ret;

err_bogus_mapping:
	pr_err("Bogus mapping 0x%"PRIx64"-0x%"PRIx64" (flags: %#x vm_file_fd: %d)\n",
	       vma_area->e->start, vma_area->e->end,
	       vma_area->e->flags, vma_area->vm_file_fd);
	goto err;

err_bogus_mapfile:
	pr_perror("Can't open %d's mapfile link %lx", pid, start);
	goto err;
}

int parse_pid_stat_small(pid_t pid, struct proc_pid_stat_small *s)
{
	char *tok, *p;
	int fd;
	int n;

	fd = open_proc(pid, "stat");
	if (fd < 0)
		return -1;

	n = read(fd, buf, BUF_SIZE);
	if (n < 1) {
		pr_err("stat for %d is corrupted\n", pid);
		close(fd);
		return -1;
	}
	close(fd);

	memset(s, 0, sizeof(*s));

	tok = strchr(buf, ' ');
	if (!tok)
		goto err;
	*tok++ = '\0';
	if (*tok != '(')
		goto err;

	s->pid = atoi(buf);

	p = strrchr(tok + 1, ')');
	if (!p)
		goto err;
	*tok = '\0';
	*p = '\0';

	strncpy(s->comm, tok + 1, sizeof(s->comm));

	n = sscanf(p + 1, " %c %d %d %d", &s->state, &s->ppid, &s->pgid, &s->sid);
	if (n < 4)
		goto err;

	return 0;

err:
	pr_err("Parsing %d's stat failed (#fields do not match)\n", pid);
	return -1;
}

int parse_pid_stat(pid_t pid, struct proc_pid_stat *s)
{
	char *tok, *p;
	int fd;
	int n;

	fd = open_proc(pid, "stat");
	if (fd < 0)
		return -1;

	n = read(fd, buf, BUF_SIZE);
	if (n < 1) {
		pr_err("stat for %d is corrupted\n", pid);
		close(fd);
		return -1;
	}
	close(fd);

	memset(s, 0, sizeof(*s));

	tok = strchr(buf, ' ');
	if (!tok)
		goto err;
	*tok++ = '\0';
	if (*tok != '(')
		goto err;

	s->pid = atoi(buf);

	p = strrchr(tok + 1, ')');
	if (!p)
		goto err;
	*tok = '\0';
	*p = '\0';

	strncpy(s->comm, tok + 1, sizeof(s->comm));

	n = sscanf(p + 1,
	       " %c %d %d %d %d %d %u %lu %lu %lu %lu "
	       "%lu %lu %ld %ld %ld %ld %d %d %llu %lu %ld %lu %lu %lu %lu "
	       "%lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld "
	       "%lu %lu %lu %lu %lu %lu %lu %d",
		&s->state,
		&s->ppid,
		&s->pgid,
		&s->sid,
		&s->tty_nr,
		&s->tty_pgrp,
		&s->flags,
		&s->min_flt,
		&s->cmin_flt,
		&s->maj_flt,
		&s->cmaj_flt,
		&s->utime,
		&s->stime,
		&s->cutime,
		&s->cstime,
		&s->priority,
		&s->nice,
		&s->num_threads,
		&s->zero0,
		&s->start_time,
		&s->vsize,
		&s->mm_rss,
		&s->rsslim,
		&s->start_code,
		&s->end_code,
		&s->start_stack,
		&s->esp,
		&s->eip,
		&s->sig_pending,
		&s->sig_blocked,
		&s->sig_ignored,
		&s->sig_handled,
		&s->wchan,
		&s->zero1,
		&s->zero2,
		&s->exit_signal,
		&s->task_cpu,
		&s->rt_priority,
		&s->policy,
		&s->delayacct_blkio_ticks,
		&s->gtime,
		&s->cgtime,
		&s->start_data,
		&s->end_data,
		&s->start_brk,
		&s->arg_start,
		&s->arg_end,
		&s->env_start,
		&s->env_end,
		&s->exit_code);
	if (n < 50)
		goto err;

	return 0;

err:
	pr_err("Parsing %d's stat failed (#fields do not match)\n", pid);
	return -1;
}

static int ids_parse(char *str, unsigned int *arr)
{
	char *end;

	arr[0] = strtol(str, &end, 10);
	arr[1] = strtol(end + 1, &end, 10);
	arr[2] = strtol(end + 1, &end, 10);
	arr[3] = strtol(end + 1, &end, 10);
	if (*end != '\n')
		return -1;
	else
		return 0;
}

static int cap_parse(char *str, unsigned int *res)
{
	int i, ret;

	for (i = 0; i < PROC_CAP_SIZE; i++) {
		ret = sscanf(str, "%08x", &res[PROC_CAP_SIZE - 1 - i]);
		if (ret != 1)
			return -1;
		str += 8;
	}

	return 0;
}

int parse_pid_status(pid_t pid, struct proc_status_creds *cr)
{
	int done = 0;
	FILE *f;
	char str[64];

	f = fopen_proc(pid, "status");
	if (f == NULL) {
		pr_perror("Can't open proc status");
		return -1;
	}

	while (done < 6 && fgets(str, sizeof(str), f)) {
		if (!strncmp(str, "Uid:", 4)) {
			if (ids_parse(str + 5, cr->uids))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "Gid:", 4)) {
			if (ids_parse(str + 5, cr->gids))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "CapInh:", 7)) {
			if (cap_parse(str + 8, cr->cap_inh))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "CapEff:", 7)) {
			if (cap_parse(str + 8, cr->cap_eff))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "CapPrm:", 7)) {
			if (cap_parse(str + 8, cr->cap_prm))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "CapBnd:", 7)) {
			if (cap_parse(str + 8, cr->cap_bnd))
				goto err_parse;

			done++;
		}
	}

	if (done != 6) {
err_parse:
		pr_err("Error parsing proc status file\n");
		fclose(f);
		return -1;
	}

	fclose(f);
	return 0;
}

struct opt2flag {
	char *opt;
	unsigned flag;
};

static int do_opt2flag(char *opt, unsigned *flags,
		const struct opt2flag *opts, char *unknown)
{
	int i;
	char *end;

	while (1) {
		end = strchr(opt, ',');
		if (end)
			*end = '\0';

		for (i = 0; opts[i].opt != NULL; i++)
			if (!strcmp(opts[i].opt, opt)) {
				(*flags) |= opts[i].flag;
				break;
			}

		if (opts[i].opt == NULL) {
			if (!unknown) {
				pr_err("Unknown option [%s]\n", opt);
				return -1;
			}

			strcpy(unknown, opt);
			unknown += strlen(opt);
			*unknown = ',';
			unknown++;
		}

		if (!end) {
			if (unknown)
				*unknown = '\0';
			break;
		} else
			opt = end + 1;
	}

	return 0;
}

static int parse_mnt_flags(char *opt, unsigned *flags)
{
	const struct opt2flag mnt_opt2flag[] = {
		{ "rw", 0, },
		{ "ro", MS_RDONLY, },
		{ "nosuid", MS_NOSUID, },
		{ "nodev", MS_NODEV, } ,
		{ "noexec", MS_NOEXEC, },
		{ "noatime", MS_NOATIME, },
		{ "nodiratime", MS_NODIRATIME, },
		{ "relatime", MS_RELATIME, },
		{ },
	};

	return do_opt2flag(opt, flags, mnt_opt2flag, NULL);
}

static int parse_sb_opt(char *opt, unsigned *flags, char *uopt)
{
	const struct opt2flag sb_opt2flag[] = {
		{ "rw", 0, },
		{ "ro", MS_RDONLY, },
		{ "sync", MS_SYNC, },
		{ "dirsync", MS_DIRSYNC, },
		{ "mad", MS_MANDLOCK, },
		{ },
	};

	return do_opt2flag(opt, flags, sb_opt2flag, uopt);
}

static int parse_mnt_opt(char *str, struct mount_info *mi, int *off)
{
	char *istr = str, *end;

	while (1) {
		end = strchr(str, ' ');
		if (!end) {
			pr_err("Error parsing mount options\n");
			return -1;
		}

		*end = '\0';
		if (!strncmp(str, "-", 1))
			break;
		else if (!strncmp(str, "shared:", 7)) {
			mi->flags |= MS_SHARED;
			mi->shared_id = atoi(str + 7);
		} else if (!strncmp(str, "master:", 7)) {
			mi->flags |= MS_SLAVE;
			mi->master_id = atoi(str + 7);
		} else if (!strncmp(str, "propagate_from:", 15)) {
			/* skip */;
		} else if (!strncmp(str, "unbindable", 11))
			mi->flags |= MS_UNBINDABLE;
		else {
			pr_err("Unknown option [%s]\n", str);
			return -1;
		}

		str = end + 1;
	}

	*off = end - istr + 1;
	return 0;
}

static int parse_mountinfo_ent(char *str, struct mount_info *new)
{
	unsigned int kmaj, kmin;
	int ret, n;
	char *opt;
	char *fstype;

	new->mountpoint = xmalloc(PATH_MAX);
	if (new->mountpoint == NULL)
		return -1;

	new->mountpoint[0] = '.';
	ret = sscanf(str, "%i %i %u:%u %ms %s %ms %n",
			&new->mnt_id, &new->parent_mnt_id,
			&kmaj, &kmin, &new->root, new->mountpoint + 1,
			&opt, &n);
	if (ret != 7) {
		xfree(new->mountpoint);
		return -1;
	}

	new->mountpoint = xrealloc(new->mountpoint, strlen(new->mountpoint) + 1);

	new->s_dev = MKKDEV(kmaj, kmin);
	new->flags = 0;
	if (parse_mnt_flags(opt, &new->flags))
		return -1;

	free(opt); /* after %ms scanf */

	str += n;
	if (parse_mnt_opt(str, new, &n))
		return -1;

	str += n;
	ret = sscanf(str, "%ms %ms %ms", &fstype, &new->source, &opt);
	if (ret != 3)
		return -1;

	ret = -1;
	new->fstype = find_fstype_by_name(fstype);

	new->options = xmalloc(strlen(opt) + 1);
	if (!new->options)
		goto err;

	if (parse_sb_opt(opt, &new->flags, new->options))
		goto err;

	ret = 0;
err:
	free(opt);
	free(fstype);
	return ret;
}

struct mount_info *parse_mountinfo(pid_t pid, struct ns_id *nsid)
{
	struct mount_info *list = NULL;
	FILE *f;
	char str[1024];

	snprintf(str, sizeof(str), "/proc/%d/mountinfo", pid);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open %d mountinfo", pid);
		return NULL;
	}

	while (fgets(str, sizeof(str), f)) {
		struct mount_info *new;
		int ret;

		new = mnt_entry_alloc();
		if (!new)
			goto err;

		new->nsid = nsid;

		new->next = list;
		list = new;

		ret = parse_mountinfo_ent(str, new);
		if (ret < 0) {
			pr_err("Bad format in %d mountinfo\n", pid);
			goto err;
		}

		pr_info("\ttype %s source %s %x %s @ %s flags %x options %s\n",
				new->fstype->name, new->source,
				new->s_dev, new->root, new->mountpoint,
				new->flags, new->options);

		if (new->fstype->parse) {
			ret = new->fstype->parse(new);
			if (ret) {
				pr_err("Failed to parse FS specific data on %s\n",
						new->mountpoint);
				goto err;
			}
		}
	}
out:
	fclose(f);
	return list;

err:
	while (list) {
		struct mount_info *next = list->next;
		mnt_entry_free(list);
		list = next;
	}
	goto out;
}

static char nybble(const char n)
{
	if (n >= '0' && n <= '9')
		return n - '0';
	else if (n >= 'A' && n <= 'F')
		return n - ('A' - 10);
	else if (n >= 'a' && n <= 'f')
		return n - ('a' - 10);
	return 0;
}

static int alloc_fhandle(FhEntry *fh)
{
	fh->n_handle = FH_ENTRY_SIZES__min_entries;
	fh->handle = xmalloc(pb_repeated_size(fh, handle));

	return fh->handle == NULL ? -1 : 0;
}

static void free_fhandle(FhEntry *fh)
{
	if (fh->handle)
		xfree(fh->handle);
}

static void parse_fhandle_encoded(char *tok, FhEntry *fh)
{
	char *d = (char *)fh->handle;
	int i = 0;

	memzero(d, pb_repeated_size(fh, handle));

	while (*tok == ' ')
		tok++;

	while (*tok) {
		if (i >= pb_repeated_size(fh, handle))
			break;
		d[i++] = (nybble(tok[0]) << 4) | nybble(tok[1]);
		if (tok[1])
			tok += 2;
		else
			break;
	}
}

#define fdinfo_field(str, field)	!strncmp(str, field":", sizeof(field))

static int parse_fdinfo_pid_s(char *pid, int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg)
{
	FILE *f;
	char str[256];
	bool entry_met = false;
	int ret = -1;

	sprintf(str, "/proc/%s/fdinfo/%d", pid, fd);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open %s to parse", str);
		return -1;
	}

	while (fgets(str, sizeof(str), f)) {
		union fdinfo_entries entry;

		if (fdinfo_field(str, "pos") ||
		    fdinfo_field(str, "flags") ||
		    fdinfo_field(str, "mnt_id")) {
			unsigned long long val;
			struct fdinfo_common *fdinfo = arg;

			if (type != FD_TYPES__UND)
				continue;
			ret = sscanf(str, "%*s %lli", &val);
			if (ret != 1)
				goto parse_err;

			if (fdinfo_field(str, "pos"))
				fdinfo->pos = val;
			else if (fdinfo_field(str, "flags"))
				fdinfo->flags = val;
			else if (fdinfo_field(str, "mnt_id"))
				fdinfo->mnt_id = val;

			entry_met = true;
			continue;
		}

		if (type == FD_TYPES__UND)
			continue;

		if (fdinfo_field(str, "eventfd-count")) {
			eventfd_file_entry__init(&entry.efd);

			if (type != FD_TYPES__EVENTFD)
				goto parse_err;
			ret = sscanf(str, "eventfd-count: %"PRIx64,
					&entry.efd.counter);
			if (ret != 1)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "tfd")) {
			eventpoll_tfd_entry__init(&entry.epl);

			if (type != FD_TYPES__EVENTPOLL)
				goto parse_err;
			ret = sscanf(str, "tfd: %d events: %x data: %"PRIx64,
					&entry.epl.tfd, &entry.epl.events, &entry.epl.data);
			if (ret != 3)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "sigmask")) {
			signalfd_entry__init(&entry.sfd);

			if (type != FD_TYPES__SIGNALFD)
				goto parse_err;
			ret = sscanf(str, "sigmask: %Lx",
					(unsigned long long *)&entry.sfd.sigmask);
			if (ret != 1)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify flags")) {
			struct fsnotify_params *p = arg;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			ret = sscanf(str, "fanotify flags:%x event-flags:%x",
				     &p->faflags, &p->evflags);
			if (ret != 2)
				goto parse_err;
			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify ino")) {
			FanotifyInodeMarkEntry ie = FANOTIFY_INODE_MARK_ENTRY__INIT;
			FhEntry f_handle = FH_ENTRY__INIT;
			int hoff;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			fanotify_mark_entry__init(&entry.ffy);
			ie.f_handle = &f_handle;
			entry.ffy.ie = &ie;

			ret = sscanf(str,
				     "fanotify ino:%"PRIx64" sdev:%x mflags:%x mask:%x ignored_mask:%x "
				     "fhandle-bytes:%x fhandle-type:%x f_handle: %n",
				     &ie.i_ino, &entry.ffy.s_dev,
				     &entry.ffy.mflags, &entry.ffy.mask, &entry.ffy.ignored_mask,
				     &f_handle.bytes, &f_handle.type,
				     &hoff);
			if (ret != 7)
				goto parse_err;

			if (alloc_fhandle(&f_handle)) {
				ret = -1;
				goto out;
			}
			parse_fhandle_encoded(str + hoff, &f_handle);

			entry.ffy.type = MARK_TYPE__INODE;
			ret = cb(&entry, arg);

			free_fhandle(&f_handle);

			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify mnt_id")) {
			FanotifyMountMarkEntry me = FANOTIFY_MOUNT_MARK_ENTRY__INIT;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			fanotify_mark_entry__init(&entry.ffy);
			entry.ffy.me = &me;

			ret = sscanf(str,
				     "fanotify mnt_id:%x mflags:%x mask:%x ignored_mask:%x",
				     &me.mnt_id, &entry.ffy.mflags,
				     &entry.ffy.mask, &entry.ffy.ignored_mask);
			if (ret != 4)
				goto parse_err;

			entry.ffy.type = MARK_TYPE__MOUNT;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "inotify wd")) {
			FhEntry f_handle = FH_ENTRY__INIT;
			int hoff;

			inotify_wd_entry__init(&entry.ify);
			entry.ify.f_handle = &f_handle;

			if (type != FD_TYPES__INOTIFY)
				goto parse_err;
			ret = sscanf(str,
					"inotify wd:%x ino:%"PRIx64" sdev:%x "
					"mask:%x ignored_mask:%x "
					"fhandle-bytes:%x fhandle-type:%x "
					"f_handle: %n",
					&entry.ify.wd, &entry.ify.i_ino, &entry.ify.s_dev,
					&entry.ify.mask, &entry.ify.ignored_mask,
					&entry.ify.f_handle->bytes, &entry.ify.f_handle->type,
					&hoff);
			if (ret != 7)
				goto parse_err;

			if (alloc_fhandle(&f_handle)) {
				ret = -1;
				goto out;
			}

			parse_fhandle_encoded(str + hoff, entry.ify.f_handle);

			ret = cb(&entry, arg);

			free_fhandle(&f_handle);

			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
	}

	ret = 0;
	if (entry_met)
		goto out;
	/*
	 * An eventpoll/inotify file may have no target fds set thus
	 * resulting in no tfd: lines in proc. This is normal.
	 */
	if (type == FD_TYPES__EVENTPOLL || type == FD_TYPES__INOTIFY)
		goto out;

	pr_err("No records of type %d found in fdinfo file\n", type);
parse_err:
	ret = -1;
	pr_perror("%s: error parsing [%s] for %d", __func__, str, type);
out:
	fclose(f);
	return ret;
}

int parse_fdinfo_pid(int pid, int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg)
{
	char pid_s[10];

	sprintf(pid_s, "%d", pid);
	return parse_fdinfo_pid_s(pid_s, fd, type, cb, arg);
}

int parse_fdinfo(int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg)
{
	return parse_fdinfo_pid_s("self", fd, type, cb, arg);
}

static int parse_file_lock_buf(char *buf, struct file_lock *fl,
				bool is_blocked)
{
	int  num;

	if (is_blocked) {
		num = sscanf(buf, "%lld: -> %s %s %s %d %x:%x:%ld %lld %s",
			&fl->fl_id, fl->fl_flag, fl->fl_type, fl->fl_option,
			&fl->fl_owner, &fl->maj, &fl->min, &fl->i_no,
			&fl->start, fl->end);
	} else {
		num = sscanf(buf, "%lld:%s %s %s %d %x:%x:%ld %lld %s",
			&fl->fl_id, fl->fl_flag, fl->fl_type, fl->fl_option,
			&fl->fl_owner, &fl->maj, &fl->min, &fl->i_no,
			&fl->start, fl->end);
	}

	if (num < 10) {
		pr_err("Invalid file lock info (%d): %s", num, buf);
		return -1;
	}

	return 0;
}

int parse_file_locks(void)
{
	struct file_lock *fl;

	FILE	*fl_locks;
	int	ret = 0;
	bool	is_blocked;

	fl_locks = fopen("/proc/locks", "r");
	if (!fl_locks) {
		pr_perror("Can't open file locks file!");
		return -1;
	}

	while (fgets(buf, BUF_SIZE, fl_locks)) {
		is_blocked = strstr(buf, "->") != NULL;

		fl = alloc_file_lock();
		if (!fl) {
			pr_perror("Alloc file lock failed!");
			ret = -1;
			goto err;
		}

		if (parse_file_lock_buf(buf, fl, is_blocked)) {
			xfree(fl);
			ret = -1;
			goto err;
		}

		if (!pid_in_pstree(fl->fl_owner)) {
			/*
			 * We only care about tasks which are taken
			 * into dump, so we only collect file locks
			 * belong to these tasks.
			 */
			xfree(fl);
			continue;
		}

		if (is_blocked) {
			/*
			 * Here the task is in the pstree.
			 * If it is blocked on a flock, when we try to
			 * ptrace-seize it, the kernel will unblock task
			 * from flock and will stop it in another place.
			 * So in dumping, a blocked file lock should never
			 * be here.
			 */
			pr_perror("We have a blocked file lock!");
			ret = -1;
			xfree(fl);
			goto err;
		}

		pr_info("lockinfo: %lld:%s %s %s %d %02x:%02x:%ld %lld %s\n",
			fl->fl_id, fl->fl_flag, fl->fl_type, fl->fl_option,
			fl->fl_owner, fl->maj, fl->min, fl->i_no,
			fl->start, fl->end);

		list_add_tail(&fl->list, &file_lock_list);
	}

err:
	fclose(fl_locks);
	return ret;
}

void free_posix_timers(struct proc_posix_timers_stat *st)
{
	while (!list_empty(&st->timers)) {
		struct proc_posix_timer *timer;
		timer = list_first_entry(&st->timers, struct proc_posix_timer, list);
		list_del(&timer->list);
		xfree(timer);
	}
}

int parse_posix_timers(pid_t pid, struct proc_posix_timers_stat *args)
{
	int ret = 0;
	int pid_t;

	FILE * file;

	char sigpid[7];
	char tidpid[4];

	struct proc_posix_timer *timer = NULL;

	INIT_LIST_HEAD(&args->timers);
	args->timer_n = 0;

	file = fopen_proc(pid, "timers");
	if (file == NULL) {
		pr_perror("Can't open posix timers file!");
		return -1;
	}

	while (1) {
		char pbuf[17]; /* 16 + eol */
		timer = xzalloc(sizeof(struct proc_posix_timer));
		if (timer == NULL)
			goto err;

		ret = fscanf(file, "ID: %ld\n"
				   "signal: %d/%16s\n"
				   "notify: %6[a-z]/%3[a-z].%d\n"
				   "ClockID: %d\n",
				&timer->spt.it_id,
				&timer->spt.si_signo, pbuf,
				sigpid, tidpid, &pid_t,
				&timer->spt.clock_id);
		if (ret != 7) {
			ret = 0;
			xfree(timer);
			if (feof(file))
				goto out;
			goto err;
		}

		timer->spt.sival_ptr = NULL;
		if (sscanf(pbuf, "%p", &timer->spt.sival_ptr) != 1 &&
		    strcmp(pbuf, "(null)")) {
			pr_err("Unable to parse '%s'\n", pbuf);
			xfree(timer);
			goto err;
		}

		if ( tidpid[0] == 't') {
			timer->spt.it_sigev_notify = SIGEV_THREAD_ID;
		} else {
			switch (sigpid[0]) {
				case 's' :
					timer->spt.it_sigev_notify = SIGEV_SIGNAL;
					break;
				case 't' :
					timer->spt.it_sigev_notify = SIGEV_THREAD;
					break;
				default :
					timer->spt.it_sigev_notify = SIGEV_NONE;
					break;
			}
		}

		list_add(&timer->list, &args->timers);
		timer = NULL;
		args->timer_n++;
	}
err:
	free_posix_timers(args);
	pr_perror("Parse error in posix timers proc file!");
	ret = -1;
out:
	fclose(file);
	return ret;
}

int parse_threads(int pid, struct pid **_t, int *_n)
{
	struct dirent *de;
	DIR *dir;
	struct pid *t = NULL;
	int nr = 1;

	if (*_t)
		t = *_t;

	dir = opendir_proc(pid, "task");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		struct pid *tmp;

		/* We expect numbers only here */
		if (de->d_name[0] == '.')
			continue;

		if (*_t == NULL) {
			tmp = xrealloc(t, nr * sizeof(struct pid));
			if (!tmp) {
				xfree(t);
				return -1;
			}
			t = tmp;
			t[nr - 1].virt = -1;
		}
		t[nr - 1].real = atoi(de->d_name);
		nr++;
	}

	closedir(dir);

	if (*_t == NULL) {
		*_t = t;
		*_n = nr - 1;
	} else
		BUG_ON(nr - 1 != *_n);

	return 0;
}

int parse_task_cgroup(int pid, struct list_head *retl, unsigned int *n)
{
	int ret = 0;
	FILE *f;

	f = fopen_proc(pid, "cgroup");
	while (fgets(buf, BUF_SIZE, f)) {
		struct cg_ctl *ncc, *cc;
		char *name, *path, *e;

		ret = -1;
		ncc = xmalloc(sizeof(*cc));
		if (!ncc)
			goto err;

		name = strchr(buf, ':') + 1;
		path = strchr(name, ':');
		e = strchr(name, '\n');
		*path++ = '\0';
		if (e)
			*e = '\0';

		ncc->name = xstrdup(name);
		ncc->path = xstrdup(path);
		if (!ncc->name || !ncc->path) {
			xfree(ncc->name);
			xfree(ncc->path);
			xfree(ncc);
			goto err;
		}

		list_for_each_entry(cc, retl, l)
			if (strcmp(cc->name, name) >= 0 && strcmp(cc->path, path) >= 0)
				break;

		list_add_tail(&ncc->l, &cc->l);
		(*n)++;
	}

	fclose(f);
	return 0;

err:
	put_ctls(retl);
	fclose(f);
	return ret;
}

void put_ctls(struct list_head *l)
{
	struct cg_ctl *c, *n;

	list_for_each_entry_safe(c, n, l, l) {
		xfree(c->name);
		xfree(c->path);
		xfree(c);
	}
}


/* Parse and create all the real controllers. This does not include things with
 * the "name=" prefix, e.g. systemd.
 */
int parse_cgroups(struct list_head *cgroups, unsigned int *n_cgroups)
{
	FILE *f;
	char buf[1024], name[1024];
	int heirarchy, ret = 0;
	struct cg_controller *cur = NULL;

	f = fopen("/proc/cgroups", "r");
	if (!f) {
		pr_perror("failed opening /proc/cgroups");
		return -1;
	}

	/* throw away the header */
	if (!fgets(buf, 1024, f)) {
		ret = -1;
		goto out;
	}

	while (fgets(buf, 1024, f)) {
		char *n;
		char found = 0;

		sscanf(buf, "%s %d", name, &heirarchy);
		list_for_each_entry(cur, cgroups, l) {
			if (cur->heirarchy == heirarchy) {
				void *m;

				found = 1;
				cur->n_controllers++;
				m = xrealloc(cur->controllers, sizeof(char *) * cur->n_controllers);
				if (!m) {
					ret = -1;
					goto out;
				}

				cur->controllers = m;
				if (!cur->controllers) {
					ret = -1;
					goto out;
				}

				n = xstrdup(name);
				if (!n) {
					ret = -1;
					goto out;
				}

				cur->controllers[cur->n_controllers-1] = n;
				break;
			}
		}

		if (!found) {
			struct cg_controller *nc = new_controller(name, heirarchy);
			if (!nc) {
				ret = -1;
				goto out;
			}
			list_add_tail(&nc->l, &cur->l);
			(*n_cgroups)++;
		}
	}

out:
	fclose(f);
	return ret;
}
