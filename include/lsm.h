#ifndef __CR_LSM_H__
#define __CR_LSM_H__

#include "pstree.h"

extern Lsmtype host_lsm_type();
extern int collect_lsm_profile(struct pstree_item *item);
extern int validate_lsm();

#endif /* __CR_LSM_H__ */
