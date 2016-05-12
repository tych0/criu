#include <stdio.h>
#include <unistd.h>

#include "files-reg.h"
#include "crtools.h"
#include "mount.h"
#include "stats.h"
#include "pstree.h"
#include "net.h"
#include "sk-inet.h"
#include "rst-malloc.h"

static int gc_prepare_namespace();
static int gc_prepare_sockets();

int cr_garbage_collect(bool show)
{
	if (check_img_inventory() < 0)
		return -1;

	if (collect_remaps_and_regfiles())
		return -1;

	if (gc_prepare_namespace())
		return -1;

	if (gc_prepare_sockets())
		return -1;

	gc_network(show);

	gc_collected_remaps(show);

	return 0;
}

static int gc_prepare_namespace()
{  
	pr_info("MAX: going to prepare_namespace\n");

	task_entries = rst_mem_alloc(sizeof(*task_entries), RM_SHREMAP);

	if (prepare_pstree())
		return -1;

	if (prepare_mnt_ns())
		return -1;

  return 0;
}

static int gc_prepare_sockets()
{
	if (collect_inet_sockets())
		return -1;

	return 0;
}
