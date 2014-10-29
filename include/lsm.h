#ifndef __CR_LSM_H__
#define __CR_LSM_H__

#include "pstree.h"

/*
 * Get the Lsmtype for the current host.
 */
extern Lsmtype host_lsm_type();

/*
 * Read the LSM profile for the pstree item
 */
extern int collect_lsm_profile(struct pstree_item *item);

/*
 * Validate that the LSM profiles can be correctly applied (must happen after
 * pstree is set up).
 */
extern int validate_lsm();

/*
 * Render the profile name in the way that the LSM wants it written to
 * /proc/<pid>/attr/current.
 */
int render_lsm_profile(char *profile, char **val);

#endif /* __CR_LSM_H__ */
