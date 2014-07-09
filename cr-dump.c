#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <sys/sendfile.h>

#include <sched.h>
#include <sys/resource.h>

#include "protobuf.h"
#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/fs.pb-c.h"
#include "protobuf/mm.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/file-lock.pb-c.h"
#include "protobuf/rlimit.pb-c.h"
#include "protobuf/siginfo.pb-c.h"

#include "asm/types.h"
#include "list.h"
#include "fdset.h"
#include "file-ids.h"
#include "kcmp-ids.h"
#include "compiler.h"
#include "crtools.h"
#include "cr_options.h"
#include "servicefd.h"
#include "syscall.h"
#include "ptrace.h"
#include "util.h"
#include "sockets.h"
#include "namespaces.h"
#include "image.h"
#include "proc_parse.h"
#include "parasite.h"
#include "parasite-syscall.h"
#include "files.h"
#include "files-reg.h"
#include "shmem.h"
#include "sk-inet.h"
#include "pstree.h"
#include "mount.h"
#include "tty.h"
#include "net.h"
#include "sk-packet.h"
#include "cpu.h"
#include "elf.h"
#include "cgroup.h"
#include "file-lock.h"
#include "page-xfer.h"
#include "kerndat.h"
#include "stats.h"
#include "mem.h"
#include "page-pipe.h"
#include "posix-timer.h"
#include "vdso.h"
#include "vma.h"
#include "cr-service.h"
#include "plugin.h"
#include "irmap.h"

#include "asm/dump.h"

#define NR_ATTEMPTS 5

static char loc_buf[PAGE_SIZE];

bool privately_dump_vma(struct vma_area *vma)
{
	/*
	 * The special areas are not dumped.
	 */
	if (!(vma->e->status & VMA_AREA_REGULAR))
		return false;

	/* No dumps for file-shared mappings */
	if (vma->e->status & VMA_FILE_SHARED)
		return false;

	/* No dumps for SYSV IPC mappings */
	if (vma->e->status & VMA_AREA_SYSVIPC)
		return false;

#ifdef CONFIG_VDSO
	/* No dumps for vDSO VVAR data */
	if (vma->e->status & VMA_AREA_VVAR)
		return false;
#endif
	if (vma_area_is(vma, VMA_ANON_SHARED))
		return false;

	if (!vma_area_is(vma, VMA_ANON_PRIVATE) &&
			!vma_area_is(vma, VMA_FILE_PRIVATE)) {
		pr_warn("Unexpected VMA area found\n");
		return false;
	}

	if (vma->e->end > TASK_SIZE)
		return false;

	return true;
}

static void close_vma_file(struct vma_area *vma)
{
	if (vma->vm_file_fd < 0)
		return;
	if (vma->e->status & VMA_AREA_SOCKET)
		return;
	if (vma->file_borrowed)
		return;

	close(vma->vm_file_fd);
}

void free_mappings(struct vm_area_list *vma_area_list)
{
	struct vma_area *vma_area, *p;

	list_for_each_entry_safe(vma_area, p, &vma_area_list->h, list) {
		close_vma_file(vma_area);
		if (!vma_area->file_borrowed)
			free(vma_area->st);
		free(vma_area);
	}

	INIT_LIST_HEAD(&vma_area_list->h);
	vma_area_list->nr = 0;
}

int collect_mappings(pid_t pid, struct vm_area_list *vma_area_list)
{
	int ret = -1;

	pr_info("\n");
	pr_info("Collecting mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_smaps(pid, vma_area_list, true);
	if (ret < 0)
		goto err;

	pr_info("Collected, longest area occupies %lu pages\n", vma_area_list->longest);
	pr_info_vma_list(&vma_area_list->h);

	pr_info("----------------------------------------\n");
err:
	return ret;
}

static int dump_sched_info(int pid, ThreadCoreEntry *tc)
{
	int ret;
	struct sched_param sp;

	BUILD_BUG_ON(SCHED_OTHER != 0); /* default in proto message */

	ret = sched_getscheduler(pid);
	if (ret < 0) {
		pr_perror("Can't get sched policy for %d", pid);
		return -1;
	}

	pr_info("%d has %d sched policy\n", pid, ret);
	tc->has_sched_policy = true;
	tc->sched_policy = ret;

	if ((ret == SCHED_RR) || (ret == SCHED_FIFO)) {
		ret = sched_getparam(pid, &sp);
		if (ret < 0) {
			pr_perror("Can't get sched param for %d", pid);
			return -1;
		}

		pr_info("\tdumping %d prio for %d\n", sp.sched_priority, pid);
		tc->has_sched_prio = true;
		tc->sched_prio = sp.sched_priority;
	}

	/*
	 * The nice is ignored for RT sched policies, but is stored
	 * in kernel. Thus we have to take it with us in the image.
	 */

	errno = 0;
	ret = getpriority(PRIO_PROCESS, pid);
	if (errno) {
		pr_perror("Can't get nice for %d", pid);
		return -1;
	}

	pr_info("\tdumping %d nice for %d\n", ret, pid);
	tc->has_sched_nice = true;
	tc->sched_nice = ret;

	return 0;
}

struct cr_fdset *glob_fdset;

static int collect_fds(pid_t pid, struct parasite_drain_fd *dfds)
{
	struct dirent *de;
	DIR *fd_dir;
	int n;

	pr_info("\n");
	pr_info("Collecting fds (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	fd_dir = opendir_proc(pid, "fd");
	if (!fd_dir)
		return -1;

	n = 0;
	while ((de = readdir(fd_dir))) {
		if (dir_dots(de))
			continue;

		if (n > PARASITE_MAX_FDS - 1)
			return -ENOMEM;

		dfds->fds[n++] = atoi(de->d_name);
	}

	dfds->nr_fds = n;
	pr_info("Found %d file descriptors\n", n);
	pr_info("----------------------------------------\n");

	closedir(fd_dir);

	return 0;
}

static int get_fd_mntid(int fd, int *mnt_id)
{
	struct fdinfo_common fdinfo = { .mnt_id = -1};

	if (parse_fdinfo(fd, FD_TYPES__UND, NULL, &fdinfo))
		return -1;

	*mnt_id = fdinfo.mnt_id;
	return 0;
}

static int fill_fd_params_special(int fd, struct fd_parms *p)
{
	*p = FD_PARMS_INIT;

	if (fstat(fd, &p->stat) < 0) {
		pr_perror("Can't fstat exe link");
		return -1;
	}

	if (get_fd_mntid(fd, &p->mnt_id))
		return -1;

	return 0;
}

static int dump_task_exe_link(pid_t pid, MmEntry *mm)
{
	struct fd_parms params;
	int fd, ret = 0;

	fd = open_proc(pid, "exe");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &params))
		return -1;

	if (fd_id_generate_special(&params, &mm->exe_file_id))
		ret = dump_one_reg_file(fd, mm->exe_file_id, &params);

	close(fd);
	return ret;
}

static int dump_task_fs(pid_t pid, struct parasite_dump_misc *misc, struct cr_fdset *fdset)
{
	struct fd_parms p;
	FsEntry fe = FS_ENTRY__INIT;
	int fd, ret;

	fe.has_umask = true;
	fe.umask = misc->umask;

	fd = open_proc(pid, "cwd");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &p))
		return -1;

	if (fd_id_generate_special(&p, &fe.cwd_id)) {
		ret = dump_one_reg_file(fd, fe.cwd_id, &p);
		if (ret < 0)
			return ret;
	}

	close(fd);

	fd = open_proc(pid, "root");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &p))
		return -1;

	if (fd_id_generate_special(&p, &fe.root_id)) {
		ret = dump_one_reg_file(fd, fe.root_id, &p);
		if (ret < 0)
			return ret;
	}

	close(fd);

	pr_info("Dumping task cwd id %#x root id %#x\n",
			fe.cwd_id, fe.root_id);

	return pb_write_one(fdset_fd(fdset, CR_FD_FS), &fe, PB_FS);
}

static inline u_int64_t encode_rlim(unsigned long val)
{
	return val == RLIM_INFINITY ? -1 : val;
}

static int dump_task_rlimits(int pid, TaskRlimitsEntry *rls)
{
	int res;

	for (res = 0; res <rls->n_rlimits ; res++) {
		struct rlimit lim;

		if (prlimit(pid, res, NULL, &lim)) {
			pr_perror("Can't get rlimit %d", res);
			return -1;
		}

		rls->rlimits[res]->cur = encode_rlim(lim.rlim_cur);
		rls->rlimits[res]->max = encode_rlim(lim.rlim_max);
	}

	return 0;
}

static int dump_filemap(pid_t pid, struct vma_area *vma_area,
		const struct cr_fdset *fdset)
{
	struct fd_parms p = FD_PARMS_INIT;
	VmaEntry *vma = vma_area->e;
	int ret = 0;
	u32 id;

	BUG_ON(!vma_area->st);
	p.stat = *vma_area->st;

	if (get_fd_mntid(vma_area->vm_file_fd, &p.mnt_id))
		return -1;

	/* Flags will be set during restore in get_filemap_fd() */

	if (fd_id_generate_special(&p, &id))
		ret = dump_one_reg_file(vma_area->vm_file_fd, id, &p);

	vma->shmid = id;
	return ret;
}

static int check_sysvipc_map_dump(pid_t pid, VmaEntry *vma)
{
	if (root_ns_mask & CLONE_NEWIPC)
		return 0;

	pr_err("Task %d with SysVIPC shmem map @%"PRIx64" doesn't live in IPC ns\n",
			pid, vma->start);
	return -1;
}

static int get_task_auxv(pid_t pid, MmEntry *mm)
{
	auxv_t mm_saved_auxv[AT_VECTOR_SIZE];
	int fd, i, ret;

	pr_info("Obtaining task auvx ...\n");

	fd = open_proc(pid, "auxv");
	if (fd < 0)
		return -1;

	ret = read(fd, mm_saved_auxv, sizeof(mm_saved_auxv));
	if (ret < 0) {
		ret = -1;
		pr_perror("Error reading %d's auxv", pid);
		goto err;
	} else {
		mm->n_mm_saved_auxv = ret / sizeof(auxv_t);
		for (i = 0; i < mm->n_mm_saved_auxv; i++)
			mm->mm_saved_auxv[i] = (u64)mm_saved_auxv[i];
	}

	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int dump_task_mm(pid_t pid, const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc,
		const struct vm_area_list *vma_area_list,
		const struct cr_fdset *fdset)
{
	MmEntry mme = MM_ENTRY__INIT;
	struct vma_area *vma_area;
	int ret = -1, i = 0;

	pr_info("\n");
	pr_info("Dumping mm (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	mme.n_vmas = vma_area_list->nr;
	mme.vmas = xmalloc(mme.n_vmas * sizeof(VmaEntry *));
	if (!mme.vmas)
		goto err;

	list_for_each_entry(vma_area, &vma_area_list->h, list) {
		VmaEntry *vma = vma_area->e;

		pr_info_vma(vma_area);

		if (!vma_entry_is(vma, VMA_AREA_REGULAR))
			ret = 0;
		else if (vma_entry_is(vma, VMA_AREA_SYSVIPC))
			ret = check_sysvipc_map_dump(pid, vma);
		else if (vma_entry_is(vma, VMA_ANON_SHARED))
			ret = add_shmem_area(pid, vma);
		else if (vma_entry_is(vma, VMA_FILE_PRIVATE) ||
				vma_entry_is(vma, VMA_FILE_SHARED))
			ret = dump_filemap(pid, vma_area, fdset);
		else if (vma_entry_is(vma, VMA_AREA_SOCKET))
			ret = dump_socket_map(vma_area);
		else
			ret = 0;
		if (ret)
			goto err;

		mme.vmas[i++] = vma;
	}

	mme.mm_start_code = stat->start_code;
	mme.mm_end_code = stat->end_code;
	mme.mm_start_data = stat->start_data;
	mme.mm_end_data = stat->end_data;
	mme.mm_start_stack = stat->start_stack;
	mme.mm_start_brk = stat->start_brk;

	mme.mm_arg_start = stat->arg_start;
	mme.mm_arg_end = stat->arg_end;
	mme.mm_env_start = stat->env_start;
	mme.mm_env_end = stat->env_end;

	mme.mm_brk = misc->brk;

	mme.dumpable = misc->dumpable;
	mme.has_dumpable = true;

	mme.n_mm_saved_auxv = AT_VECTOR_SIZE;
	mme.mm_saved_auxv = xmalloc(pb_repeated_size(&mme, mm_saved_auxv));
	if (!mme.mm_saved_auxv)
		goto err;

	if (get_task_auxv(pid, &mme))
		goto err;

	if (dump_task_exe_link(pid, &mme))
		goto err;

	ret = pb_write_one(fdset_fd(fdset, CR_FD_MM), &mme, PB_MM);
	xfree(mme.mm_saved_auxv);
err:
	return ret;
}

static int dump_task_creds(struct parasite_ctl *ctl,
			   const struct cr_fdset *fds,
			   struct proc_status_creds *cr)
{
	CredsEntry ce = CREDS_ENTRY__INIT;

	pr_info("\n");
	pr_info("Dumping creds for %d)\n", ctl->pid.real);
	pr_info("----------------------------------------\n");

	ce.uid   = cr->uids[0];
	ce.gid   = cr->gids[0];
	ce.euid  = cr->uids[1];
	ce.egid  = cr->gids[1];
	ce.suid  = cr->uids[2];
	ce.sgid  = cr->gids[2];
	ce.fsuid = cr->uids[3];
	ce.fsgid = cr->gids[3];

	BUILD_BUG_ON(CR_CAP_SIZE != PROC_CAP_SIZE);

	ce.n_cap_inh = CR_CAP_SIZE;
	ce.cap_inh = cr->cap_inh;
	ce.n_cap_prm = CR_CAP_SIZE;
	ce.cap_prm = cr->cap_prm;
	ce.n_cap_eff = CR_CAP_SIZE;
	ce.cap_eff = cr->cap_eff;
	ce.n_cap_bnd = CR_CAP_SIZE;
	ce.cap_bnd = cr->cap_bnd;

	if (parasite_dump_creds(ctl, &ce) < 0)
		return -1;

	return pb_write_one(fdset_fd(fds, CR_FD_CREDS), &ce, PB_CREDS);
}

static int get_task_futex_robust_list(pid_t pid, ThreadCoreEntry *info)
{
	struct robust_list_head *head = NULL;
	size_t len = 0;
	int ret;

	ret = sys_get_robust_list(pid, &head, &len);
	if (ret == -ENOSYS) {
		/*
		 * If the kernel says get_robust_list is not implemented, then
		 * check whether set_robust_list is also not implemented, in
		 * that case we can assume it is empty, since set_robust_list
		 * is the only way to populate it. This case is possible when
		 * "futex_cmpxchg_enabled" is unset in the kernel.
		 *
		 * The following system call should always fail, even if it is
		 * implemented, in which case it will return -EINVAL because
		 * len should be greater than zero.
		 */
		if (sys_set_robust_list(NULL, 0) != -ENOSYS)
			goto err;

		head = NULL;
		len = 0;
	} else if (ret) {
		goto err;
	}

	info->futex_rla		= encode_pointer(head);
	info->futex_rla_len	= (u32)len;

	return 0;

err:
	pr_err("Failed obtaining futex robust list on %d\n", pid);
	return -1;
}

static int get_task_personality(pid_t pid, u32 *personality)
{
	FILE *file = NULL;
	int ret = -1;

	pr_info("Obtaining personality ... ");

	file = fopen_proc(pid, "personality");
	if (!file)
		goto err;

	if (!fgets(loc_buf, sizeof(loc_buf), file)) {
		pr_perror("Can't read task personality");
		goto err;
	}

	*personality = atoi(loc_buf);
	ret = 0;

err:
	if (file)
		fclose(file);
	return ret;
}

static DECLARE_KCMP_TREE(vm_tree, KCMP_VM);
static DECLARE_KCMP_TREE(fs_tree, KCMP_FS);
static DECLARE_KCMP_TREE(files_tree, KCMP_FILES);
static DECLARE_KCMP_TREE(sighand_tree, KCMP_SIGHAND);

static int dump_task_kobj_ids(struct pstree_item *item)
{
	int new;
	struct kid_elem elem;
	int pid = item->pid.real;
	TaskKobjIdsEntry *ids = item->ids;

	elem.pid = pid;
	elem.idx = 0; /* really 0 for all */
	elem.genid = 0; /* FIXME optimize */

	new = 0;
	ids->vm_id = kid_generate_gen(&vm_tree, &elem, &new);
	if (!ids->vm_id || !new) {
		pr_err("Can't make VM id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->fs_id = kid_generate_gen(&fs_tree, &elem, &new);
	if (!ids->fs_id || !new) {
		pr_err("Can't make FS id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->files_id = kid_generate_gen(&files_tree, &elem, &new);
	if (!ids->files_id || (!new && !shared_fdtable(item))) {
		pr_err("Can't make FILES id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->sighand_id = kid_generate_gen(&sighand_tree, &elem, &new);
	if (!ids->sighand_id || !new) {
		pr_err("Can't make IO id for %d\n", pid);
		return -1;
	}

	return 0;
}

int get_task_ids(struct pstree_item *item)
{
	int ret;

	item->ids = xmalloc(sizeof(*item->ids));
	if (!item->ids)
		goto err;

	task_kobj_ids_entry__init(item->ids);

	if (item->state != TASK_DEAD) {
		ret = dump_task_kobj_ids(item);
		if (ret)
			goto err_free;

		ret = dump_task_ns_ids(item);
		if (ret)
			goto err_free;
	}

	return 0;

err_free:
	xfree(item->ids);
	item->ids = NULL;
err:
	return -1;
}

static int dump_task_ids(struct pstree_item *item, const struct cr_fdset *cr_fdset)
{
	return pb_write_one(fdset_fd(cr_fdset, CR_FD_IDS), item->ids, PB_IDS);
}

int dump_thread_core(int pid, CoreEntry *core, const struct parasite_dump_thread *ti)
{
	int ret;
	ThreadCoreEntry *tc = core->thread_core;

	ret = get_task_futex_robust_list(pid, tc);
	if (!ret)
		ret = dump_sched_info(pid, tc);
	if (!ret) {
		core_put_tls(core, ti->tls);
		CORE_THREAD_ARCH_INFO(core)->clear_tid_addr = encode_pointer(ti->tid_addr);
		BUG_ON(!tc->sas);
		copy_sas(tc->sas, &ti->sas);
		if (ti->pdeath_sig) {
			tc->has_pdeath_sig = true;
			tc->pdeath_sig = ti->pdeath_sig;
		}
	}

	return ret;
}

static int dump_task_core_all(struct pstree_item *item,
		const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc,
		const struct cr_fdset *cr_fdset)
{
	int fd_core = fdset_fd(cr_fdset, CR_FD_CORE);
	CoreEntry *core = item->core[0];
	pid_t pid = item->pid.real;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = get_task_personality(pid, &core->tc->personality);
	if (ret)
		goto err;

	strncpy((char *)core->tc->comm, stat->comm, TASK_COMM_LEN);
	core->tc->flags = stat->flags;
	core->tc->task_state = item->state;
	core->tc->exit_code = 0;

	ret = dump_thread_core(pid, core, &misc->ti);
	if (ret)
		goto err;

	ret = dump_task_rlimits(pid, core->tc->rlimits);
	if (ret)
		goto err;

	core->tc->has_cg_set = true;
	ret = dump_task_cgroup(item, &core->tc->cg_set);
	if (ret)
		goto err;

	ret = pb_write_one(fd_core, core, PB_CORE);
	if (ret < 0)
		goto err;

err:
	pr_info("----------------------------------------\n");

	return ret;
}

static int parse_children(pid_t pid, pid_t **_c, int *_n)
{
	FILE *file;
	char *tok;
	pid_t *ch = NULL;
	int nr = 1;
	DIR *dir;
	struct dirent *de;

	dir = opendir_proc(pid, "task");
	if (dir == NULL)
		return -1;

	while ((de = readdir(dir))) {
		if (dir_dots(de))
			continue;

		file = fopen_proc(pid, "task/%s/children", de->d_name);
		if (!file)
			goto err;

		if (!(fgets(loc_buf, sizeof(loc_buf), file)))
			loc_buf[0] = 0;

		fclose(file);

		tok = strtok(loc_buf, " \n");
		while (tok) {
			pid_t *tmp = xrealloc(ch, nr * sizeof(pid_t));
			if (!tmp)
				goto err;
			ch = tmp;
			ch[nr - 1] = atoi(tok);
			nr++;
			tok = strtok(NULL, " \n");
		}

	}

	*_c = ch;
	*_n = nr - 1;

	closedir(dir);
	return 0;
err:
	closedir(dir);
	xfree(ch);
	return -1;
}

static int collect_task(struct pstree_item *item);
static int get_children(struct pstree_item *item)
{
	pid_t *ch;
	int ret, i, nr_children, nr_inprogress;
	struct pstree_item *c;

	ret = parse_children(item->pid.real, &ch, &nr_children);
	if (ret < 0)
		return ret;

	nr_inprogress = 0;
	for (i = 0; i < nr_children; i++) {
		pid_t pid = ch[i];

		/* Is it already frozen? */
		list_for_each_entry(c, &item->children, sibling)
			if (c->pid.real == pid)
				break;

		if (&c->sibling != &item->children)
			continue;

		nr_inprogress++;

		pr_info("Seized task %d, state %d\n", pid, ret);

		c = alloc_pstree_item();
		if (c == NULL) {
			ret = -1;
			goto free;
		}

		ret = seize_task(pid, item->pid.real, &item->pgid, &item->sid);
		if (ret < 0) {
			/*
			 * Here is a race window between parse_children() and seize(),
			 * so the task could die for these time.
			 * Don't worry, will try again on the next attempt. The number
			 * of attempts is restricted, so it will exit if something
			 * really wrong.
			 */
			ret = 0;
			xfree(c);
			continue;
		}

		c->pid.real = ch[i];
		c->parent = item;
		c->state = ret;
		list_add_tail(&c->sibling, &item->children);

		/* Here is a recursive call (Depth-first search) */
		ret = collect_task(c);
		if (ret < 0)
			goto free;
	}
free:
	xfree(ch);
	return ret < 0 ? ret : nr_inprogress;
}

static void unseize_task_and_threads(const struct pstree_item *item, int st)
{
	int i;

	if (item->state == TASK_DEAD)
		return;

	/*
	 * The st is the state we want to switch tasks into,
	 * the item->state is the state task was in when we seized one.
	 */

	unseize_task(item->pid.real, item->state, st);

	for (i = 1; i < item->nr_threads; i++)
		ptrace(PTRACE_DETACH, item->threads[i].real, NULL, NULL);
}

static void pstree_switch_state(struct pstree_item *root_item, int st)
{
	struct pstree_item *item = root_item;

	pr_info("Unfreezing tasks into %d\n", st);
	for_each_pstree_item(item)
		unseize_task_and_threads(item, st);
}

static pid_t item_ppid(const struct pstree_item *item)
{
	item = item->parent;
	return item ? item->pid.real : -1;
}

static int seize_threads(struct pstree_item *item,
				struct pid *threads, int nr_threads)
{
	int i = 0, ret, j, nr_inprogress, nr_stopped = 0;

	if ((item->state == TASK_DEAD) && (nr_threads > 1)) {
		pr_err("Zombies with threads are not supported\n");
		goto err;
	}

	/* The number of threads can't be less than allready frozen */
	item->threads = xrealloc(item->threads, nr_threads * sizeof(struct pid));
	if (item->threads == NULL)
		return -1;

	if (item->nr_threads == 0) {
		item->threads[0].real = item->pid.real;
		item->nr_threads = 1;
	}

	nr_inprogress = 0;
	for (i = 0; i < nr_threads; i++) {
		pid_t pid = threads[i].real;
		if (item->pid.real == pid)
			continue;

		for (j = 0; j < item->nr_threads; j++)
			if (pid == item->threads[j].real)
				break;

		if (j != item->nr_threads)
			continue;
		nr_inprogress++;

		pr_info("\tSeizing %d's %d thread\n",
				item->pid.real, pid);

		ret = seize_task(pid, item_ppid(item), NULL, NULL);
		if (ret < 0) {
			/*
			 * Here is a race window between parse_threads() and seize(),
			 * so the task could die for these time.
			 * Don't worry, will try again on the next attempt. The number
			 * of attempts is restricted, so it will exit if something
			 * really wrong.
			 */
			continue;
		}

		BUG_ON(item->nr_threads + 1 > nr_threads);
		item->threads[item->nr_threads].real = pid;
		item->nr_threads++;

		if (ret == TASK_DEAD) {
			pr_err("Zombie thread not supported\n");
			goto err;
		}

		if (ret == TASK_STOPPED) {
			nr_stopped++;
		}
	}

	if (nr_stopped && nr_stopped != nr_inprogress) {
		pr_err("Individually stopped threads not supported\n");
		goto err;
	}

	return nr_inprogress;
err:
	return -1;
}

static int collect_threads(struct pstree_item *item)
{
	int ret, attempts = NR_ATTEMPTS;
	struct pid *t;
	int nr, nr_inprogress;

	nr_inprogress = 1;
	while (nr_inprogress > 0 && attempts) {
		attempts--;

		t = NULL;
		nr = 0;

		ret = parse_threads(item->pid.real, &t, &nr);
		if (ret < 0)
			break;

		nr_inprogress = seize_threads(item, t, nr);
		xfree(t);
		if (nr_inprogress < 0)
			break;

	}

	if (nr_inprogress && attempts)
		return -1;

	return 0;
}

static int collect_task(struct pstree_item *item)
{
	int ret, nr_inprogress, attempts = NR_ATTEMPTS;

	ret = collect_threads(item);
	if (ret < 0)
		goto err_close;

	if (item->state == TASK_DEAD)
		return 0;

	/* Depth-first search (DFS) is used for traversing a process tree. */
	nr_inprogress = 1;
	while (nr_inprogress && attempts) {
		attempts--;

		/*
		 * Freeze children and children of children, etc.
		 * Then check again, that nobody is reparented.
		 */
		nr_inprogress = get_children(item);
		if (nr_inprogress < 0)
			goto err_close;
	}

	if (attempts == 0)
		goto err_close;

	if ((item->state == TASK_DEAD) && !list_empty(&item->children)) {
		pr_err("Zombie with children?! O_o Run, run, run!\n");
		goto err_close;
	}

	close_pid_proc();

	pr_info("Collected %d in %d state\n", item->pid.real, item->state);
	return 0;

err_close:
	close_pid_proc();
	return -1;
}

int collect_pstree_ids(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item)
		if (get_task_ids(item))
			return -1;

	return 0;
}

static int collect_pstree(pid_t pid)
{
	int ret;

	timing_start(TIME_FREEZING);

	root_item = alloc_pstree_item();
	if (root_item == NULL)
		return -1;

	root_item->pid.real = pid;
	ret = seize_task(pid, -1, &root_item->pgid, &root_item->sid);
	if (ret < 0)
		goto err;
	pr_info("Seized task %d, state %d\n", pid, ret);
	root_item->state = ret;

	ret = collect_task(root_item);
	if (ret < 0)
		goto err;

	timing_stop(TIME_FREEZING);
	timing_start(TIME_FROZEN);

	return 0;
err:
	pstree_switch_state(root_item, TASK_ALIVE);
	return -1;
}

static int collect_file_locks(void)
{
	if (parse_file_locks())
		return -1;

	if (opts.handle_file_locks)
		/*
		 * If the handle file locks option(-l) is set,
		 * collect work is over.
		 */
		return 0;

	/*
	 * If the handle file locks option is not set, we need to do
	 * the check, any file locks hold by tasks in our pstree is
	 * not allowed.
	 *
	 * It's hard to do it carefully, there might be some other
	 * issues like tasks beyond pstree would use flocks hold by
	 * dumping tasks, but we can't know it in dumping time.
	 * We need to make sure these flocks only used by dumping tasks.
	 * We might have to do the check that this option would only
	 * be used by container dumping.
	 */
	if (!list_empty(&file_lock_list)) {
		pr_err("Some file locks are hold by dumping tasks!"
			  "You can try --" OPT_FILE_LOCKS " to dump them.\n");
		return -1;
	}

	return 0;

}

static int dump_task_thread(struct parasite_ctl *parasite_ctl,
				const struct pstree_item *item, int id)
{
	struct pid *tid = &item->threads[id];
	CoreEntry *core = item->core[id];
	pid_t pid = tid->real;
	int ret = -1, fd_core;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parasite_dump_thread_seized(parasite_ctl, id, tid, core);
	if (ret) {
		pr_err("Can't dump thread for pid %d\n", pid);
		goto err;
	}

	fd_core = open_image(CR_FD_CORE, O_DUMP, tid->virt);
	if (fd_core < 0)
		goto err;

	ret = pb_write_one(fd_core, core, PB_CORE);

	close(fd_core);
err:
	pr_info("----------------------------------------\n");
	return ret;
}

static int dump_one_zombie(const struct pstree_item *item,
			   const struct proc_pid_stat *pps)
{
	CoreEntry *core;
	int ret = -1, fd_core;

	core = core_entry_alloc(0, 1);
	if (!core)
		return -1;

	strncpy((char *)core->tc->comm, pps->comm, TASK_COMM_LEN);
	core->tc->task_state = TASK_DEAD;
	core->tc->exit_code = pps->exit_code;

	fd_core = open_image(CR_FD_CORE, O_DUMP, item->pid.virt);
	if (fd_core < 0)
		goto err;

	ret = pb_write_one(fd_core, core, PB_CORE);
	close(fd_core);
err:
	core_entry_free(core);
	return ret;
}

static int dump_signal_queue(pid_t tid, int fd, bool group)
{
	struct ptrace_peeksiginfo_args arg;
	siginfo_t siginfo[32]; /* One page or all non-rt signals */
	int ret, i = 0, j, nr;

	pr_debug("Dump %s signals of %d\n", group ? "shared" : "private", tid);

	arg.nr = sizeof(siginfo) / sizeof(siginfo_t);
	arg.flags = 0;
	if (group)
		arg.flags |= PTRACE_PEEKSIGINFO_SHARED;

	for (; ; ) {
		arg.off = i;

		ret = ptrace(PTRACE_PEEKSIGINFO, tid, &arg, siginfo);
		if (ret < 0) {
			if (errno == EIO) {
				pr_warn("ptrace doesn't support PTRACE_PEEKSIGINFO\n");
				ret = 0;
			} else
				pr_perror("ptrace");
			break;
		}

		if (ret == 0)
			break;
		nr = ret;

		for (j = 0; j < nr; j++) {
			SiginfoEntry sie = SIGINFO_ENTRY__INIT;

			sie.siginfo.len = sizeof(siginfo_t);
			sie.siginfo.data = (void *) (siginfo + j);

			ret = pb_write_one(fd, &sie, PB_SIGINFO);
			if (ret < 0)
				break;
			i++;
		}
	}

	return ret;
}

static int dump_thread_signals(struct pid *tid)
{
	int fd, ret;

	fd = open_image(CR_FD_PSIGNAL, O_DUMP, tid->virt);
	if (fd < 0)
		return -1;
	ret = dump_signal_queue(tid->real, fd, false);
	close(fd);

	return ret;
}

static int dump_task_signals(pid_t pid, struct pstree_item *item,
		struct cr_fdset *cr_fdset)
{
	int i, ret;

	ret = dump_signal_queue(pid, fdset_fd(cr_fdset, CR_FD_SIGNAL), true);
	if (ret) {
		pr_err("Can't dump pending signals (pid: %d)\n", pid);
		return -1;
	}

	for (i = 0; i < item->nr_threads; i++) {
		ret = dump_thread_signals(&item->threads[i]);
		if (ret)
			return -1;
	}

	return 0;
}

static struct proc_pid_stat pps_buf;

static int dump_task_threads(struct parasite_ctl *parasite_ctl,
			     const struct pstree_item *item)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		/* Leader is already dumped */
		if (item->pid.real == item->threads[i].real) {
			item->threads[i].virt = item->pid.virt;
			continue;
		}
		if (dump_task_thread(parasite_ctl, item, i))
			return -1;
	}

	return 0;
}

/*
 * What this routine does is just reads pid-s of dead
 * tasks in item's children list from item's ns proc.
 *
 * It does *not* find wihch real pid corresponds to
 * which virtual one, but it's not required -- all we
 * need to dump for zombie can be found in the same
 * ns proc.
 */

static int fill_zombies_pids(struct pstree_item *item)
{
	struct pstree_item *child;
	int i, nr;
	pid_t *ch;

	if (parse_children(item->pid.virt, &ch, &nr) < 0)
		return -1;

	list_for_each_entry(child, &item->children, sibling) {
		if (child->pid.virt < 0)
			continue;
		for (i = 0; i < nr; i++) {
			if (ch[i] == child->pid.virt) {
				ch[i] = -1;
				break;
			}
		}
	}

	i = 0;
	list_for_each_entry(child, &item->children, sibling) {
		if (child->pid.virt > 0)
			continue;
		for (; i < nr; i++) {
			if (ch[i] < 0)
				continue;
			child->pid.virt = ch[i];
			ch[i] = -1;
			break;
		}
		BUG_ON(i == nr);
	}

	xfree(ch);

	return 0;
}

static int dump_zombies(void)
{
	struct pstree_item *item;
	int ret = -1;
	int pidns = root_ns_mask & CLONE_NEWPID;

	if (pidns && set_proc_fd(get_service_fd(CR_PROC_FD_OFF)))
		return -1;

	/*
	 * We dump zombies separately becase for pid-ns case
	 * we'd have to resolve their pids w/o parasite via
	 * target ns' proc.
	 */

	for_each_pstree_item(item) {
		if (item->state != TASK_DEAD)
			continue;

		if (item->pid.virt < 0) {
			if (!pidns)
				item->pid.virt = item->pid.real;
			else if (root_item == item) {
				pr_err("A root task is dead\n");
				goto err;
			} else if (fill_zombies_pids(item->parent))
				goto err;
		}

		pr_info("Obtaining zombie stat ... ");
		if (parse_pid_stat(item->pid.virt, &pps_buf) < 0)
			goto err;

		item->sid = pps_buf.sid;
		item->pgid = pps_buf.pgid;

		BUG_ON(!list_empty(&item->children));
		if (dump_one_zombie(item, &pps_buf) < 0)
			goto err;
	}

	ret = 0;
err:
	if (pidns)
		close_proc();

	return ret;
}

static int pre_dump_one_task(struct pstree_item *item, struct list_head *ctls)
{
	pid_t pid = item->pid.real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;

	INIT_LIST_HEAD(&vmas.h);
	vmas.nr = 0;

	pr_info("========================================\n");
	pr_info("Pre-dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (item->state == TASK_STOPPED) {
		pr_warn("Stopped tasks are not supported\n");
		return 0;
	}

	if (item->state == TASK_DEAD)
		return 0;

	ret = collect_mappings(pid, &vmas);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = -1;
	parasite_ctl = parasite_infect_seized(pid, item, &vmas, NULL, 0);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err_free;
	}

	ret = parasite_fixup_vdso(parasite_ctl, pid, &vmas);
	if (ret) {
		pr_err("Can't fixup vdso VMAs (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = predump_task_files(pid);
	if (ret) {
		pr_err("Pre-dumping files failed (pid: %d)\n", pid);
		goto err_cure;
	}

	parasite_ctl->pid.virt = item->pid.virt = misc.pid;

	ret = parasite_dump_pages_seized(parasite_ctl, &vmas, &parasite_ctl->mem_pp);
	if (ret)
		goto err_cure;

	if (parasite_cure_remote(parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
	list_add_tail(&parasite_ctl->pre_list, ctls);
err_free:
	free_mappings(&vmas);
err:
	return ret;

err_cure:
	if (parasite_cure_seized(parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
	goto err_free;
}

static int dump_one_task(struct pstree_item *item)
{
	pid_t pid = item->pid.real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;
	struct cr_fdset *cr_fdset = NULL;
	struct parasite_drain_fd *dfds = NULL;
	struct proc_posix_timers_stat proc_args;
	struct proc_status_creds cr;

	INIT_LIST_HEAD(&vmas.h);
	vmas.nr = 0;

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (item->state == TASK_DEAD)
		/*
		 * zombies are dumped separately in dump_zombies()
		 */
		return 0;

	pr_info("Obtaining task stat ... ");
	ret = parse_pid_stat(pid, &pps_buf);
	if (ret < 0)
		goto err;

	ret = parse_pid_status(pid, &cr);
	if (ret)
		goto err;

	if (!may_dump(&cr)) {
		ret = -1;
		pr_err("Check uid (pid: %d) failed\n", pid);
		goto err;
	}

	ret = collect_mappings(pid, &vmas);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	dfds = xmalloc(sizeof(*dfds));
	if (!dfds)
		goto err;

	ret = collect_fds(pid, dfds);
	if (ret) {
		pr_err("Collect fds (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = parse_posix_timers(pid, &proc_args);
	if (ret < 0) {
		pr_err("Can't read posix timers file (pid: %d)\n", pid);
		goto err;
	}

	ret = -1;
	parasite_ctl = parasite_infect_seized(pid, item, &vmas, dfds, proc_args.timer_n);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	if (root_ns_mask & CLONE_NEWPID && root_item == item) {
		int pfd;

		pfd = parasite_get_proc_fd_seized(parasite_ctl);
		if (pfd < 0) {
			pr_err("Can't get proc fd (pid: %d)\n", pid);
			goto err_cure_fdset;
		}

		if (install_service_fd(CR_PROC_FD_OFF, pfd) < 0)
			goto err_cure_fdset;

		close(pfd);
	}

	ret = parasite_fixup_vdso(parasite_ctl, pid, &vmas);
	if (ret) {
		pr_err("Can't fixup vdso VMAs (pid: %d)\n", pid);
		goto err_cure_fdset;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure_fdset;
	}

	parasite_ctl->pid.virt = item->pid.virt = misc.pid;
	item->sid = misc.sid;
	item->pgid = misc.pgid;

	pr_info("sid=%d pgid=%d pid=%d\n",
		item->sid, item->pgid, item->pid.virt);

	if (item->sid == 0) {
		pr_err("A session leader of %d(%d) is outside of its pid namespace\n",
			item->pid.real, item->pid.virt);
		ret = -1;
		goto err_cure;
	}

	ret = -1;
	cr_fdset = cr_task_fdset_open(item->pid.virt, O_DUMP);
	if (!cr_fdset)
		goto err_cure;

	ret = dump_task_ids(item, cr_fdset);
	if (ret) {
		pr_err("Dump ids (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	if (!shared_fdtable(item)) {
		ret = dump_task_files_seized(parasite_ctl, item, dfds);
		if (ret) {
			pr_err("Dump files (pid: %d) failed with %d\n", pid, ret);
			goto err_cure;
		}
	}

	if (opts.handle_file_locks) {
		ret = dump_task_file_locks(parasite_ctl, cr_fdset, dfds);
		if (ret) {
			pr_err("Dump file locks (pid: %d) failed with %d\n",
				pid, ret);
			goto err_cure;
		}
	}

	ret = parasite_dump_pages_seized(parasite_ctl, &vmas, NULL);
	if (ret)
		goto err_cure;

	ret = parasite_dump_sigacts_seized(parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Can't dump sigactions (pid: %d) with parasite\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_itimers_seized(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump itimers (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_posix_timers_seized(&proc_args, parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump posix timers (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = dump_task_core_all(item, &pps_buf, &misc, cr_fdset);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	ret = dump_task_threads(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump threads\n");
		goto err_cure;
	}

	ret = dump_task_creds(parasite_ctl, cr_fdset, &cr);
	if (ret) {
		pr_err("Dump creds (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = parasite_cure_seized(parasite_ctl);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = dump_task_mm(pid, &pps_buf, &misc, &vmas, cr_fdset);
	if (ret) {
		pr_err("Dump mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_fs(pid, &misc, cr_fdset);
	if (ret) {
		pr_err("Dump fs (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_signals(pid, item, cr_fdset);
	if (ret) {
		pr_err("Dump %d signals failed %d\n", pid, ret);
		goto err;
	}

	close_cr_fdset(&cr_fdset);
err:
	close_pid_proc();
	free_mappings(&vmas);
	xfree(dfds);
	return ret;

err_cure:
	close_cr_fdset(&cr_fdset);
err_cure_fdset:
	parasite_cure_seized(parasite_ctl);
	goto err;
}

int cr_pre_dump_tasks(pid_t pid)
{
	struct pstree_item *item;
	int ret = -1;
	LIST_HEAD(ctls);
	struct parasite_ctl *ctl, *n;

	if (!opts.track_mem) {
		pr_info("Enforcing memory tracking for pre-dump.\n");
		opts.track_mem = true;
	}

	if (opts.final_state == TASK_DEAD) {
		pr_info("Enforcing tasks run after pre-dump.\n");
		opts.final_state = TASK_ALIVE;
	}

	if (init_stats(DUMP_STATS))
		goto err;

	if (kerndat_init())
		goto err;

	if (irmap_load_cache())
		goto err;

	if (cpu_init())
		goto err;

	if (vdso_init())
		goto err;

	if (connect_to_page_server())
		goto err;

	if (collect_pstree(pid))
		goto err;

	if (gen_predump_ns_mask())
		goto err;

	if (collect_mnt_namespaces() < 0)
		goto err;

	for_each_pstree_item(item)
		if (pre_dump_one_task(item, &ctls))
			goto err;

	ret = 0;
err:
	pstree_switch_state(root_item,
			ret ? TASK_ALIVE : opts.final_state);
	free_pstree(root_item);

	timing_stop(TIME_FROZEN);

	pr_info("Pre-dumping tasks' memory\n");
	list_for_each_entry_safe(ctl, n, &ctls, pre_list) {
		struct page_xfer xfer;

		pr_info("\tPre-dumping %d\n", ctl->pid.virt);
		timing_start(TIME_MEMWRITE);
		ret = open_page_xfer(&xfer, CR_FD_PAGEMAP, ctl->pid.virt);
		if (ret < 0)
			break;

		ret = page_xfer_dump_pages(&xfer, ctl->mem_pp, 0);

		xfer.close(&xfer);

		if (ret)
			break;

		timing_stop(TIME_MEMWRITE);

		destroy_page_pipe(ctl->mem_pp);
		list_del(&ctl->pre_list);
		parasite_cure_local(ctl);
	}

	if (irmap_predump_run())
		ret = -1;

	if (disconnect_from_page_server())
		ret = -1;

	if (ret)
		pr_err("Pre-dumping FAILED.\n");
	else {
		write_stats(DUMP_STATS);
		pr_info("Pre-dumping finished successfully\n");
	}

	return ret;
}

int cr_dump_tasks(pid_t pid)
{
	struct pstree_item *item;
	int post_dump_ret = 0;
	int ret = -1;

	pr_info("========================================\n");
	pr_info("Dumping processes (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (init_stats(DUMP_STATS))
		goto err;

	if (cr_plugin_init())
		goto err;

	if (kerndat_init())
		goto err;

	if (irmap_load_cache())
		goto err;

	if (cpu_init())
		goto err;

	if (vdso_init())
		goto err;

	if (parse_cg_info())
		goto err;

	if (write_img_inventory())
		goto err;

	if (connect_to_page_server())
		goto err;

	/*
	 * The collect_pstree will also stop (PTRACE_SEIZE) the tasks
	 * thus ensuring that they don't modify anything we collect
	 * afterwards.
	 */

	if (collect_pstree(pid))
		goto err;

	if (collect_pstree_ids())
		goto err;

	if (network_lock())
		goto err;

	if (collect_file_locks())
		goto err;

	if (dump_mnt_namespaces() < 0)
		goto err;

	if (collect_sockets(pid))
		goto err;

	glob_fdset = cr_glob_fdset_open(O_DUMP);
	if (!glob_fdset)
		goto err;

	for_each_pstree_item(item) {
		if (dump_one_task(item))
			goto err;
	}

	if (dump_verify_tty_sids())
		goto err;

	if (dump_zombies())
		goto err;

	if (dump_pstree(root_item))
		goto err;

	if (root_ns_mask)
		if (dump_namespaces(root_item, root_ns_mask) < 0)
			goto err;

	ret = dump_cgroups();
	if (ret)
		goto err;

	ret = cr_dump_shmem();
	if (ret)
		goto err;

	ret = fix_external_unix_sockets();
	if (ret)
		goto err;

	ret = tty_verify_active_pairs();
	if (ret)
		goto err;

	fd_id_show_tree();
err:
	if (disconnect_from_page_server())
		ret = -1;

	close_cr_fdset(&glob_fdset);

	cr_plugin_fini();

	if (!ret) {
		/*
		 * It might be a migration case, where we're asked
		 * to dump everything, then some script transfer
		 * image on a new node and we're supposed to kill
		 * dumpee because it continue running somewhere
		 * else.
		 *
		 * Thus ask user via script if we're to break
		 * checkpoint.
		 */
		post_dump_ret = run_scripts("post-dump");
		if (post_dump_ret) {
			post_dump_ret = WEXITSTATUS(post_dump_ret);
			pr_info("Post dump script passed with %d\n", post_dump_ret);
		}
	}

	/*
	 * Dump is complete at this stage. To choose what
	 * to do next we need to consider the following
	 * scenarios
	 *
	 *  - error happened during checkpoint: just clean up
	 *    everything and continue execution of the dumpee;
	 *
	 *  - dump successed but post-dump script returned
	 *    some ret code: same as in previous scenario --
	 *    just clean up everything and continue execution,
	 *    we will return script ret code back to criu caller
	 *    and it's up to a caller what to do with running instance
	 *    of the dumpee -- either kill it, or continue running;
	 *
	 *  - dump successed but -R option passed, pointing that
	 *    we're asked to continue execution of the dumpee. It's
	 *    assumed that a user will use post-dump script to keep
	 *    consistency of the FS and other resources, we simply
	 *    start rollback procedure and cleanup everyhting.
	 */
	if (ret || post_dump_ret || opts.final_state == TASK_ALIVE) {
		network_unlock();
		delete_link_remaps();
	}
	pstree_switch_state(root_item,
			    (ret || post_dump_ret) ?
			    TASK_ALIVE : opts.final_state);
	timing_stop(TIME_FROZEN);
	free_pstree(root_item);
	free_file_locks();
	free_link_remaps();

	close_service_fd(CR_PROC_FD_OFF);

	if (ret) {
		kill_inventory();
		pr_err("Dumping FAILED.\n");
	} else {
		write_stats(DUMP_STATS);
		pr_info("Dumping finished successfully\n");
	}

	return post_dump_ret ? : (ret != 0);
}
