#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "pstree.h"
#include "util.h"

#include "protobuf.h"
#include "protobuf/pstree.pb-c.h"

#ifdef CONFIG_HAS_APPARMOR
#include <sys/apparmor.h>
#endif

#ifdef CONFIG_HAS_SELINUX
#include <selinux/selinux.h>
#endif

static Lsmtype	lsmtype;
static int	(*get_label)(pid_t, char **) = NULL;
static char	*name = NULL;

static int apparmor_get_label(pid_t pid, char **profile_name)
{
	FILE *f;
	char *space;

	f = fopen_proc(pid, "attr/current");
	if (!f)
		return -1;

	pr_info("scanfing\n");
	if (fscanf(f, "%ms", profile_name) != 1) {
		fclose(f);
		pr_perror("err scanfing\n");
		return -1;
	}

	fclose(f);

	/*
	 * A profile name can be followed by an enforcement mode, e.g.
	 *	lxc-default-with-nesting (enforced)
	 * but the profile name is just the part before the space.
	 */
	space = strstr(*profile_name, " ");
	if (space)
		*space = 0;

	/*
	 * An "unconfined" value means there is no profile, so we don't need to
	 * worry about trying to restore one.
	 */
	if (strcmp(*profile_name, "unconfined") == 0)
		*profile_name = NULL;

	return 0;
}

#ifdef CONFIG_HAS_SELINUX
static int selinux_get_label(pid_t pid, char **profile_name)
{
	security_context_t ctx;

	if (getpidcon_raw(pid, &ctx) < 0) {
		pr_perror("getting selinux profile failed");
		return -1;
	}

	*profile_name = xstrdup((char *)ctx);
	freecon(ctx);
	if (!*profile_name)
		return -1;

	return 0;
}
#endif

static void get_host_lsm()
{
	if (access("/sys/kernel/security/apparmor", F_OK) == 0) {
		get_label = apparmor_get_label;
		lsmtype = LSMTYPE__APPARMOR;
		name = "apparmor";
		return;
	}

#ifdef CONFIG_HAS_SELINUX
	if (access("/sys/kernel/security/selinux", F_OK) == 0) {
		get_label = selinux_get_label;
		lsmtype = LSMTYPE__SELINUX;
		name = "selinux";
		return;
	}
#endif

	get_label = NULL;
	lsmtype = LSMTYPE__NO_LSM;
	name = "none";
}

Lsmtype host_lsm_type()
{
	if (name == NULL)
		get_host_lsm();

	return lsmtype;
}

int collect_lsm_profile(struct pstree_item *item)
{
	if (name == NULL)
		get_host_lsm();

	if (lsmtype == LSMTYPE__NO_LSM)
		return 0;

	pr_info("collecting lsm profile %s\n", name);

	/*
	 * Here and in validate(), we store the lsm_profile in core[0], since
	 * thats what dump_task_core_all seems to use for the task core for
	 * this pstree item.
	 */
	if (get_label(item->pid.real, &item->core[0]->lsm_profile) < 0)
		return -1;

	if (item->core[0]->lsm_profile)
		pr_info("%d has lsm profile %s\n", item->pid.real, item->core[0]->lsm_profile);

	return 0;
}

// in inventory.c
extern Lsmtype image_lsm;

int validate_lsm()
{
	struct pstree_item *it;

	if (name == NULL)
		get_host_lsm();

	if (image_lsm == LSMTYPE__NO_LSM || image_lsm == lsmtype)
		return 0;

	/*
	 * This is really only a problem if the processes have actually
	 * specified an LSM profile. If not, we won't restore anything anyway,
	 * so it's fine.
	 */
	pr_warn("lsm types do not match: host %d migratee %d\n", lsmtype, image_lsm);

	for_each_pstree_item(it) {
		if (it->core[0]->lsm_profile) {
			pr_err("mismatched lsm types and lsm profile specified\n");
			return -1;
		}
	}

	return 0;
}
