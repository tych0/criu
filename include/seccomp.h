#ifndef __CR_SECCOMP_H__
#define __CR_SECCOMP_H__

#include <linux/seccomp.h>
#include <linux/filter.h>

#include "protobuf/core.pb-c.h"

#ifndef SECCOMP_MODE_DISABLED
#define SECCOMP_MODE_DISABLED 0
#endif

#ifndef SECCOMP_MODE_STRICT
#define SECCOMP_MODE_STRICT 1
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

struct pstree_item *item;

extern int collect_seccomp_filters(void);
extern int prepare_seccomp_filters(void);
extern int get_seccomp_fd(struct pstree_item *item, CoreEntry *core);
extern int stop_seccompd(void);
#endif
