#define LOG_PREFIX	"cg: "
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <ftw.h>
#include <libgen.h>
#include "list.h"
#include "xmalloc.h"
#include "cgroup.h"
#include "pstree.h"
#include "proc_parse.h"
#include "util.h"
#include "fdset.h"
#include "protobuf.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/cgroup.pb-c.h"

/*
 * This structure describes set of controller groups
 * a task lives in. The cg_ctl entries are stored in
 * the @ctls list sorted by the .name field and then
 * by the .path field.
 */

struct cg_set {
	u32			id;
	struct list_head	l;
	unsigned int 		n_ctls;
	struct list_head	ctls;
};

static LIST_HEAD(cg_sets);
static unsigned int n_sets;
static CgSetEntry **rst_sets;
static char *cg_yard;
static struct cg_set *root_cgset; /* Set root item lives in */
static struct cg_set *criu_cgset; /* Set criu process lives in */
static u32 cg_set_ids = 1;

static LIST_HEAD(cgroups);
static unsigned int n_cgroups;
static struct mount_info *cg_mntinfo;

static CgSetEntry *find_rst_set_by_id(u32 id)
{
	int i;

	for (i = 0; i < n_sets; i++)
		if (rst_sets[i]->id == id)
			return rst_sets[i];

	return NULL;
}

#define CGCMP_MATCH	1	/* check for exact match */
#define CGCMP_ISSUB	2	/* check set is subset of ctls */

static bool cg_set_compare(struct cg_set *set, struct list_head *ctls, int what)
{
	struct list_head *l1 = &set->ctls, *l2 = ctls;

	while (1) {
		struct cg_ctl *c1 = NULL, *c2 = NULL;

		if (l1->next != &set->ctls)
			c1 = list_first_entry(l1, struct cg_ctl, l);
		if (l2->next != ctls)
			c2 = list_first_entry(l2, struct cg_ctl, l);

		if (!c1 || !c2) /* Nowhere to move next */
			return !c1 && !c2; /* Both lists scanned -- match */

		if (strcmp(c1->name, c2->name))
			return false;

		switch (what) {
		case CGCMP_MATCH:
			if (strcmp(c1->path, c2->path))
				return false;

			break;
		case CGCMP_ISSUB:
			if (!strstartswith(c1->path, c2->path))
				return false;

			break;
		}

		l1 = l1->next;
		l2 = l2->next;
	}
}

static struct cg_set *get_cg_set(struct list_head *ctls, unsigned int n_ctls)
{
	struct cg_set *cs;

	list_for_each_entry(cs, &cg_sets, l)
		if (cg_set_compare(cs, ctls, CGCMP_MATCH)) {
			pr_debug(" `- Existing css %d found\n", cs->id);
			put_ctls(ctls);
			return cs;
		}

	pr_debug(" `- New css ID %d\n", cg_set_ids);
	cs = xmalloc(sizeof(*cs));
	if (cs) {
		cs->id = cg_set_ids++;
		INIT_LIST_HEAD(&cs->ctls);
		list_splice(ctls, &cs->ctls);
		cs->n_ctls = n_ctls;
		list_add_tail(&cs->l, &cg_sets);
		n_sets++;

		if (log_get_loglevel() >= LOG_DEBUG) {
			struct cg_ctl *ctl;

			list_for_each_entry(ctl, &cs->ctls, l)
				pr_debug("    `- [%s] -> [%s]\n", ctl->name, ctl->path);
		}
	}

	return cs;
}

struct cg_controller *new_controller(const char *name, int heirarchy)
{
	struct cg_controller *nc = xmalloc(sizeof(*nc));
	if (!nc)
		return NULL;

	nc->controllers = xmalloc(sizeof(char *));
	if (!nc->controllers) {
		xfree(nc);
		return NULL;
	}

	nc->controllers[0] = xstrdup(name);
	if (!nc->controllers[0]) {
		xfree(nc->controllers);
		xfree(nc);
		return NULL;
	}

	nc->n_controllers = 1;
	nc->heirarchy = heirarchy;

	nc->n_heads = 0;
	INIT_LIST_HEAD(&nc->heads);

	return nc;
}

int parse_cg_info(void)
{
	if (parse_cgroups(&cgroups, &n_cgroups) < 0)
		return -1;

	cg_mntinfo = parse_mountinfo(getpid(), NULL);

	if (!cg_mntinfo)
		return -1;
	return 0;
}

static int get_cgroup_mount_point(const char *controller, char *path)
{
	struct mount_info *m;
	char name[1024];

	for (m = cg_mntinfo; m != NULL; m = m->next) {
		if (strcmp(m->fstype->name, "cgroup") == 0) {
			char *start, *end;

			start = strstr(m->options, "name=");
			if (start) {
				/* strlen("name=") == 5 */
				start = start + 5;

				end = strstr(start, ",");
				if (end) {
					strncpy(name, start, end - start);
					name[end - start] = '\0';
				} else
					strcpy(name, start);
			} else {
				start = strrchr(m->mountpoint, '/');
				if (!start) {
					pr_err("bad path %s\n", m->mountpoint);
					return -1;
				}
				strcpy(name, start+1);
			}

			if (strcmp(name, controller) == 0) {
				/* skip the leading '.' in mountpoint */
				strcpy(path, m->mountpoint + 1);
				return 0;
			}
		}
	}

	return -1;
}

/* This is for use in add_cgroup() as additional arguments for the ftw()
 * callback */
static struct cg_controller	*current_controller;

#define EXACT_MATCH	0
#define PARENT_MATCH	1
#define NO_MATCH	2

static int find_dir(const char *path, struct list_head *dirs, struct cgroup_dir **rdir)
{
	struct cgroup_dir *d;
	list_for_each_entry(d, dirs, siblings) {
		if (strcmp(d->path, path) == 0) {
			*rdir = d;
			return EXACT_MATCH;
		}

		if (strstartswith(path, d->path)) {
			int ret = find_dir(path, &d->children, rdir);
			if (ret == NO_MATCH) {
				*rdir = d;
				return PARENT_MATCH;
			}
			return ret;

		}
	}

	return NO_MATCH;
}

static int add_cgroup(const char *fpath, const struct stat *sb, int typeflag)
{
	struct cgroup_dir *ncd = NULL, *match;
	int ret = 0;
	char pbuf[PATH_MAX];

	if (typeflag == FTW_D) {
		FILE *f;
		int mtype;
		struct mount_info *mi;

		strncpy(pbuf, fpath, PATH_MAX);

		pr_info("adding cgroup %s\n", fpath);

		ncd = xmalloc(sizeof(*ncd));
		if (!ncd) {
			ret = -1;
			goto out;
		}
		ncd->path = NULL;

		for (mi = cg_mntinfo; mi != NULL; mi = mi->next) {
			if (is_path_prefix(fpath, mi->mountpoint + 1)) {
				ncd->path = xstrdup(fpath + strlen(mi->mountpoint));
				if (!ncd->path) {
					ret = -1;
					goto out;
				}
				break;
			}
		}

		if (!ncd->path) {
			pr_err("couldn't find %s in mountinfo\n", fpath);
			ret = -1;
			goto out;
		}

		mtype = find_dir(ncd->path, &current_controller->heads, &match);

		switch (mtype) {
		/* ignore co-mounted cgroups */
		case EXACT_MATCH:
			goto out;
		case PARENT_MATCH:
			list_add_tail(&ncd->siblings, &match->children);
			match->n_children++;
			break;
		case NO_MATCH:
			list_add_tail(&ncd->siblings, &current_controller->heads);
			current_controller->n_heads++;
			break;
		}

		INIT_LIST_HEAD(&ncd->children);
		ncd->n_children = 0;
		ncd->controller = current_controller;

		ncd->flags = 0;

		snprintf(pbuf, PATH_MAX, "%s/memory.limit_in_bytes", fpath);
		f = fopen(pbuf, "r");
		if (f) {
			if (fscanf(f, "%" SCNu64, &ncd->mem_limit) != 1) {
				pr_err("Failed scanning %s\n", pbuf);
				ret = -1;
				goto out;
			}
			ncd->flags |= HAS_MEM_LIMIT;
			fclose(f);
		}

		snprintf(pbuf, PATH_MAX, "%s/cpu.shares", fpath);
		f = fopen(pbuf, "r");
		if (f) {
			if (fscanf(f, "%" SCNu32, &ncd->cpu_shares) != 1) {
				pr_err("Failed scanning %s for u32\n", pbuf);
				ret = -1;
				goto out;
			}
			ncd->flags |= HAS_CPU_SHARES;
			fclose(f);
		}

		return 0;
	}

out:
	if (ncd) {
		if (ncd->path)
			xfree(ncd->path);
		xfree(ncd);
	}

	return ret;
}

static int collect_cgroups(struct list_head *ctls)
{
	struct cg_ctl *cc;
	int ret = 0;

	list_for_each_entry(cc, ctls, l) {
		char path[PATH_MAX];
		char *name, mount_point[PATH_MAX];
		struct cg_controller *cg;
		int i;

		if (strstartswith(cc->name, "name="))
			name = cc->name + 5;
		else
			name = cc->name;

		if (get_cgroup_mount_point(name, mount_point) < 0) {
			/* Someone is trying to dump a process that is in
			 * a controller that isn't mounted, so we mount it for
			 * them.
			 */
			char opts[1024], prefix[] = ".criu.cgmounts.XXXXXX";

			if (mkdtemp(prefix) == NULL) {
				pr_perror("can't make dir for cg mounts\n");
				return -1;
			}

			if (name == cc->name)
				sprintf(opts, "%s", name);
			else
				sprintf(opts, "none,%s", cc->name);

			if (mount("none", prefix, "cgroup", 0, opts) < 0) {
				pr_perror("couldn't mount %s\n", opts);
				return -1;
			}

			strcpy(mount_point, prefix);
		}

		snprintf(path, PATH_MAX, "%s/%s", mount_point, cc->path);

		current_controller = NULL;

		/* We should get all the "real" (i.e. not name=systemd type)
		 * controller from parse_cgroups(), so find that controller if
		 * it exists. */
		list_for_each_entry(cg, &cgroups, l) {
			for (i = 0; i < cg->n_controllers; i++) {
				if (strcmp(cg->controllers[i], cc->name) == 0) {
					current_controller = cg;
					break;
				}
			}
		}

		if (!current_controller) {
			/* only allow "fake" controllers to be created this way */
			if (!strstartswith(cc->name, "name=")) {
				pr_err("controller %s not found\n", cc->name);
				return -1;
			} else {
				struct cg_controller *nc = new_controller(cc->name, -1);
				list_add_tail(&nc->l, &cg->l);
				n_cgroups++;
				current_controller = nc;
			}
		}

		ret = ftw(path, add_cgroup, 4);
		if (ret < 0) {
			pr_perror("failed walking %s for empty cgroups\n", path);
			return ret;
		}
	}

	return 0;
}

int dump_task_cgroup(struct pstree_item *item, u32 *cg_id)
{
	int pid;
	LIST_HEAD(ctls);
	unsigned int n_ctls = 0;
	struct cg_set *cs;

	if (item)
		pid = item->pid.real;
	else
		pid = getpid();

	pr_info("Dumping cgroups for %d\n", pid);
	if (parse_task_cgroup(pid, &ctls, &n_ctls))
		return -1;

	if (item == root_item && collect_cgroups(&ctls) < 0)
		return -1;

	cs = get_cg_set(&ctls, n_ctls);
	if (!cs)
		return -1;

	if (!item) {
		BUG_ON(criu_cgset);
		criu_cgset = cs;
		pr_info("Set %d is criu one\n", cs->id);
	} else if (item == root_item) {
		BUG_ON(root_cgset);
		root_cgset = cs;
		pr_info("Set %d is root one\n", cs->id);
	}

	*cg_id = cs->id;
	return 0;
}

static int dump_cg_dirs(struct list_head *dirs, size_t n_dirs, CgroupDirEntry ***ents)
{
	struct cgroup_dir *cur;
	CgroupDirEntry *cde;
	void *m;
	int i = 0;

	m = xmalloc(n_dirs * (sizeof(CgroupDirEntry *) + sizeof(CgroupDirEntry)));
	*ents = m;
	if (!m)
		return -1;

	cde = m + n_dirs * sizeof(CgroupDirEntry *);

	list_for_each_entry(cur, dirs, siblings) {
		cgroup_dir_entry__init(cde);

		cde->path = cur->path;
		cde->has_mem_limit = cur->flags & HAS_MEM_LIMIT;
		cde->mem_limit = cur->mem_limit;
		cde->has_cpu_shares = cur->flags & HAS_CPU_SHARES;
		cde->cpu_shares = cur->cpu_shares;

		cde->n_children = cur->n_children;
		if (cur->n_children > 0)
			if (dump_cg_dirs(&cur->children, cur->n_children, &cde->children) < 0) {
				xfree(*ents);
				return -1;
			}
		(*ents)[i++] = cde++;
	}

	return 0;
}

static int dump_controllers(CgroupEntry *cg)
{
	struct cg_controller *cur;
	CgControllerEntry *ce;
	void *m;
	int i;

	cg->n_controllers = n_cgroups;
	m = xmalloc(n_cgroups * (sizeof(CgControllerEntry *) + sizeof(CgControllerEntry)));
	cg->controllers = m;
	ce = m + cg->n_controllers * sizeof(CgControllerEntry *);
	if (!m)
		return -1;

	i = 0;
	list_for_each_entry(cur, &cgroups, l) {
		cg_controller_entry__init(ce);

		ce->controllers = cur->controllers;
		ce->n_controllers = cur->n_controllers;
		ce->n_dirs = cur->n_heads;
		if (ce->n_dirs > 0)
			if (dump_cg_dirs(&cur->heads, cur->n_heads, &ce->dirs) < 0) {
				xfree(cg->controllers);
				return -1;
			}
		cg->controllers[i++] = ce++;
	}

	return 0;
}


static int dump_sets(CgroupEntry *cg)
{
	struct cg_set *set;
	struct cg_ctl *ctl;
	int s, c;
	void *m;
	CgSetEntry *se;
	CgMemberEntry *ce;

	pr_info("Dumping %d sets\n", n_sets - 1);

	cg->n_sets = n_sets - 1;
	m = xmalloc(cg->n_sets * (sizeof(CgSetEntry *) + sizeof(CgSetEntry)));
	cg->sets = m;
	se = m + cg->n_sets * sizeof(CgSetEntry *);
	if (!m)
		return -1;

	s = 0;
	list_for_each_entry(set, &cg_sets, l) {
		if (set == criu_cgset)
			continue;

		/*
		 * Check that all sets we've found that tasks live in are
		 * subsets of the one root task lives in
		 */

		pr_info(" `- Dumping %d set (%d ctls)\n", set->id, set->n_ctls);
		if (!cg_set_compare(set, &root_cgset->ctls, CGCMP_ISSUB)) {
			pr_err("Set %d is not subset of %d\n",
					set->id, root_cgset->id);
			return -1;
		}

		/*
		 * Now encode them onto the image entry
		 */

		cg_set_entry__init(se);
		se->id = set->id;

		se->n_ctls = set->n_ctls;
		m = xmalloc(se->n_ctls * (sizeof(CgMemberEntry *) + sizeof(CgMemberEntry)));
		se->ctls = m;
		ce = m + se->n_ctls * sizeof(CgMemberEntry *);
		if (!m)
			return -1;

		c = 0;
		list_for_each_entry(ctl, &set->ctls, l) {
			pr_info("   `- Dumping %s of %s\n", ctl->name, ctl->path);
			cg_member_entry__init(ce);
			ce->name = ctl->name;
			ce->path = ctl->path;
			se->ctls[c++] = ce++;
		}

		cg->sets[s++] = se++;
	}

	return 0;
}

int dump_cgroups(void)
{
	CgroupEntry cg = CGROUP_ENTRY__INIT;

	BUG_ON(!criu_cgset || !root_cgset);

	/*
	 * Check whether root task lives in its own set as compared
	 * to criu. If yes, we should not dump anything, but make
	 * sure no other sets exist. The latter case can be supported,
	 * but requires some trickery and is hardly needed at the
	 * moment.
	 */

	if (root_cgset == criu_cgset) {
		if (!list_is_singular(&cg_sets)) {
			pr_err("Non supported sub-cgroups found\n");
			return -1;
		}

		pr_info("All tasks in criu's cgroups. Nothing to dump.\n");
		return 0;
	}

	if (dump_sets(&cg))
		return -1;
	if (dump_controllers(&cg))
		return -1;

	pr_info("Writing CG image\n");
	return pb_write_one(fdset_fd(glob_fdset, CR_FD_CGROUP), &cg, PB_CGROUP);
}

static int move_in_cgroup(CgSetEntry *se)
{
	int cg, i;

	pr_info("Move into %d\n", se->id);
	cg = get_service_fd(CGROUP_YARD);
	for (i = 0; i < se->n_ctls; i++) {
		char aux[1024];
		int fd, err;
		CgMemberEntry *ce = se->ctls[i];

		if (strstartswith(ce->name, "name="))
			sprintf(aux, "%s/%s/tasks", ce->name + 5, ce->path);
		else
			sprintf(aux, "%s/%s/tasks", ce->name, ce->path);
		pr_debug("  `-> %s\n", aux);
		err = fd = openat(cg, aux, O_WRONLY);
		if (fd >= 0) {
			/*
			 * Writing zero into this file moves current
			 * task w/o any permissions checks :)
			 */
			err = write(fd, "0", 1);
			close(fd);
		}

		if (err < 0) {
			pr_perror("Can't move into %s (%d/%d)\n",
					aux, err, fd);
			return -1;
		}
	}

	close_service_fd(CGROUP_YARD);
	return 0;
}

int prepare_task_cgroup(struct pstree_item *me)
{
	CgSetEntry *se;
	u32 current_cgset;

	if (!me->rst->cg_set)
		return 0;

	if (me->parent)
		current_cgset = me->parent->rst->cg_set;
	else
		current_cgset = root_cg_set;

	if (me->rst->cg_set == current_cgset) {
		pr_info("Cgroups %d inherited from parent\n", current_cgset);
		close_service_fd(CGROUP_YARD);
		return 0;
	}

	se = find_rst_set_by_id(me->rst->cg_set);
	if (!se) {
		pr_err("No set %d found\n", me->rst->cg_set);
		return -1;
	}

	return move_in_cgroup(se);
}

void fini_cgroup(void)
{
	if (!cg_yard)
		return;

	close_service_fd(CGROUP_YARD);
	umount2(cg_yard, MNT_DETACH);
	rmdir(cg_yard);
	xfree(cg_yard);
}

static int prepare_cgroup_dirs(char *paux, size_t off, CgroupDirEntry **ents, size_t n_ents)
{
	size_t i, my_off;
	CgroupDirEntry *e;

	for (i = 0; i < n_ents; i++) {
		e = ents[i];

		my_off = sprintf(paux + off, "/%s", e->path);

		if (mkdirp(paux)) {
			pr_perror("Can't make cgroup dir %s", paux);
			return -1;
		}

		if (e->has_mem_limit) {
			FILE *f;

			sprintf(paux + my_off + off, "/memory.limit_in_bytes");

			f = fopen(paux, "w+");
			if (!f) {
				pr_perror("Couldn't open %s for writing\n", paux);
				return -1;
			}

			fprintf(f, "%" SCNu64, e->mem_limit);
			fclose(f);
		}

		if (e->has_cpu_shares) {
			FILE *f;

			sprintf(paux + my_off + off, "/cpu.shares");

			f = fopen(paux, "w+");
			if (!f) {
				pr_perror("Couldn't open %s for writing\n", paux);
				return -1;
			}

			fprintf(f, "%" SCNu32, e->cpu_shares);
			fclose(f);
		}

		prepare_cgroup_dirs(paux, off, e->children, e->n_children);
	}

	return 0;
}

/*
 * Prepare the CGROUP_YARD service descriptor. This guy is
 * tmpfs mount with the set of ctl->name directories each
 * one having the respective cgroup mounted.
 *
 * It's required for two reasons.
 *
 * First, if we move more than one task into cgroups it's
 * faster to have cgroup tree visible by them all in sime
 * single place. Searching for this thing existing in the
 * criu's space is not nice, as parsing /proc/mounts is not
 * very fast, other than this not all cgroups may be mounted.
 *
 * Second, when we have user-namespaces support we will
 * loose the ability to mount cgroups on-demand, so prepare
 * them in advance.
 */

static int prepare_cgroup_sfd(CgroupEntry *ce)
{
	int off, i;
	char paux[PATH_MAX];

	pr_info("Preparing cgroups yard\n");

	off = sprintf(paux, ".criu.cgyard.XXXXXX");
	if (mkdtemp(paux) == NULL) {
		pr_perror("Can't make temp cgyard dir");
		return -1;
	}

	cg_yard = xstrdup(paux);
	if (!cg_yard) {
		rmdir(paux);
		return -1;
	}

	if (mount("none", cg_yard, "tmpfs", 0, NULL)) {
		pr_perror("Can't mount tmpfs in cgyard");
		goto err;
	}

	if (mount("none", cg_yard, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't make cgyard private");
		goto err;
	}

	for (i = 0; i < ce->n_controllers; i++) {
		CgControllerEntry *ctrl = ce->controllers[i];
		int j, name_off, opt_off;
		char *name, opt[1024];

		if (ctrl->n_controllers < 1) {
			pr_err("Each cg_controller_entry must have at least 1 controller");
			goto err;
		}

		if (strstartswith(ctrl->controllers[0], "name=")) {
			name = ctrl->controllers[0] + 5;
			opt_off = sprintf(opt, "none,%s", ctrl->controllers[0]);
		} else {
			name = ctrl->controllers[0];
			opt_off = sprintf(opt, "%s", ctrl->controllers[0]);
		}

		for (j = 1; j < ctrl->n_controllers; j++) {
			name = ctrl->controllers[i];
			opt_off += sprintf(opt + opt_off, ",%s", ctrl->controllers[i]);
		}

		name_off = sprintf(paux + off, "/%s", name);

		if (mkdir(paux, 0700)) {
			pr_perror("Can't make cgyard subdir %s", paux);
			goto err;
		}

		if (mount("none", paux, "cgroup", 0, opt) < 0) {
			pr_perror("Can't mount %s cgyard", paux);
			goto err;
		}

		if (prepare_cgroup_dirs(paux, off + name_off, ctrl->dirs, ctrl->n_dirs))
			goto err;

	}

	pr_debug("Opening %s as cg yard\n", cg_yard);
	i = open(cg_yard, O_DIRECTORY);
	if (i < 0) {
		pr_perror("Can't open cgyard");
		goto err;
	}

	off = install_service_fd(CGROUP_YARD, i);
	close(i);
	if (off < 0)
		goto err;

	return 0;

err:
	fini_cgroup();
	return -1;
}

int prepare_cgroup(void)
{
	int fd, ret;
	CgroupEntry *ce;

	fd = open_image(CR_FD_CGROUP, O_RSTR | O_OPT);
	if (fd < 0) {
		if (errno == ENOENT) /* backward compatibility */
			return 0;
		else
			return fd;
	}

	ret = pb_read_one_eof(fd, &ce, PB_CGROUP);
	close(fd);
	if (ret <= 0) /* Zero is OK -- no sets there. */
		return ret;

	n_sets = ce->n_sets;
	rst_sets = ce->sets;
	if (n_sets)
		/*
		 * We rely on the fact that all sets contain the same
		 * set of controllers. This is checked during dump
		 * with cg_set_compare(CGCMP_ISSUB) call.
		 */
		ret = prepare_cgroup_sfd(ce);
	else
		ret = 0;

	return ret;
}
