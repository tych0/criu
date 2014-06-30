#define LOG_PREFIX	"cg: "
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <ftw.h>
#include <libgen.h>
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
 * the @ctls list sorted by the .name field.
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

struct cg_controller *new_controller(const char *name, unsigned int heirarchy)
{
	struct cg_controller *nc = xmalloc(sizeof(*nc));
	if (!nc)
		return NULL;

	nc->controllers = xmalloc(sizeof(char*));
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

/* Parse and create all the real controllers. This does not include things with
 * the "name=" prefix, e.g. systemd.
 */
int parse_cgroups()
{
	FILE *f = fopen("/proc/cgroups", "r");
	char buf[1024], name[1024];
	uint32_t heirarchy;
	struct cg_controller *cur = NULL;

	if (!f) {
		pr_perror("failed opening /proc/cgroups");
		return -1;
	}

	/* throw away the header */
	if (!fgets(buf, 1024, f))
		return 0;

	while(fgets(buf, 1024, f))
	{
		char *n;
		char found = 0;

		sscanf(buf, "%s" "%" SCNu32, name, &heirarchy);
		list_for_each_entry(cur, &cgroups, l) {
			if (cur->heirarchy == heirarchy)
			{
				found = 1;
				cur->n_controllers++;
				cur->controllers = xrealloc(cur->controllers,
				                            sizeof(char*) * cur->n_controllers);
				if (!cur->controllers)
					return -1;

				n = xstrdup(name);
				if (!n)
					return -1;

				cur->controllers[cur->n_controllers-1] = n;
				break;
			}
		}

		if (!found)
		{
			struct cg_controller *nc = new_controller(name, heirarchy);
			if (!nc)
				return -1;
			list_add_tail(&nc->l, &cur->l);
			n_cgroups++;
		}
	}

	return 0;
}

static struct cg_controller	*current_controller;

#define EXACT_MATCH	0
#define PARENT_MATCH	1
#define NO_MATCH	2

static int find_dir(const char *path, struct list_head *dirs, struct cgroup_dir **rdir)
{
	struct cgroup_dir *d;
	list_for_each_entry(d, dirs, siblings) {
		pr_info("%s %s\n", d->path, path);
		if (strcmp(d->path, path) == 0) {
			*rdir = d;
			return EXACT_MATCH;
		}

		if (strncmp(d->path, path, strlen(d->path))) {
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
	char pbuf[PATH_MAX], *name, *path;


	if (typeflag == FTW_D)
	{
		FILE *f;
		int mtype;

		strncpy(pbuf, fpath, PATH_MAX);

		pr_info("adding cgroup %s\n", fpath);

		ncd = xmalloc(sizeof(*ncd));
		if(!ncd)
		{
			ret = -1;
			goto out;
		}

		/* skip strlen("/sys/fs/cgroup/") */
		name = pbuf + 15;
		path = strchr(name, '/');
		ncd->path = xstrdup(path);
		if (!ncd->path)
		{
			ret = -1;
			goto out;
		}

		mtype = find_dir(path, &current_controller->heads, &match);

		switch(mtype) {
			/* ignore co-mounted cgroups */
			case EXACT_MATCH :
				goto out;
			case PARENT_MATCH :
				list_add_tail(&ncd->siblings, &match->children);
				match->n_children++;
				break;
			case NO_MATCH :
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
		if (f)
		{
			if (fscanf(f, "%" SCNu64, &ncd->mem_limit) != 1)
			{
				pr_err("Failed scanning %s\n", pbuf);
				ret = -1;
				goto out;
			}
			ncd->flags |= HAS_MEM_LIMIT;
			fclose(f);
		}

		snprintf(pbuf, PATH_MAX, "%s/cpu.shares", fpath);
		f = fopen(pbuf, "r");
		if (f)
		{
			if (fscanf(f, "%" SCNu32, &ncd->cpu_shares) != 1)
			{
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
	if(ncd) {
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
		char *name;
		struct cg_controller *cg;
		int i;

		if (strstartswith(cc->name, "name="))
			name = cc->name + 5;
		else
			name = cc->name;

		/* TODO: parse /proc/self/mountinfo for correct directories */
		snprintf(path, PATH_MAX, "/sys/fs/cgroup/%s%s", name, cc->path);

		current_controller = NULL;

		/* Use the previously allocated struct for this controller if
		 * there is one */
		list_for_each_entry(cg, &cgroups, l) {
			for (i = 0; i < cg->n_controllers; i++)
			{
				if (strcmp(cg->controllers[i], cc->name) == 0) {
					current_controller = cg;
					break;
				}
			}
		}

		if (!current_controller)
		{
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

		if ((ret = ftw(path, add_cgroup, 4)) < 0)
		{
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

	if (collect_cgroups(&ctls) < 0)
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

int dump_cg_dirs(struct list_head *dirs, size_t n_dirs, CgroupDirEntry ***ents)
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
	if(!m)
		return -1;

	i = 0;
	list_for_each_entry(cur, &cgroups, l) {
		cg_controller_entry__init(ce);

		ce->controllers = cur->controllers;
		ce->n_controllers = cur->n_controllers;
		// TODO: id?
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
	MemberEntry *ce;

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
		m = xmalloc(se->n_ctls * (sizeof(MemberEntry *) + sizeof(MemberEntry)));
		se->ctls = m;
		ce = m + se->n_ctls * sizeof(MemberEntry *);
		if (!m)
			return -1;

		c = 0;
		list_for_each_entry(ctl, &set->ctls, l) {
			pr_info("   `- Dumping %s of %s\n", ctl->name, ctl->path);
			member_entry__init(ce);
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
		MemberEntry *ce = se->ctls[i];

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

static int prepare_cgroup_dirs(char* paux, size_t off, CgroupDirEntry **ents, size_t n_ents)
{
	size_t i;
	CgroupDirEntry *e;

	for (i = 0; i < n_ents; i++)
	{
		e = ents[i];

		sprintf(paux + off, "/%s", e->path);

		if (mkdirp(paux)) {
			pr_perror("Can't make cgroup dir %s", paux);
			return -1;
		}

		/* TODO: restore mem_limit, cpu_shares */
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

		for (j = 1; j < ctrl->n_controllers; j++)
		{
			name = ctrl->controllers[i];
			opt_off += sprintf(opt + opt_off, ",%s", ctrl->controllers[i]);
		}

		name_off = sprintf(paux + off, "/%s", name);

		if (mkdir(paux, 0700)) {
			pr_perror("Can't make cgyard subdir %s", paux);
			goto err;
		}

		pr_info("opt: %s\n", opt);
		if (mount("none", paux, "cgroup", 0, opt) < 0) {
			pr_perror("Can't mount %s cgyard", paux);
			goto err;
		}

		if(prepare_cgroup_dirs(paux, off + name_off, ctrl->dirs, ctrl->n_dirs))
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
	return prepare_cgroup_sfd(ce);
}
