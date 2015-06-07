/*
 * Copyright (C) 2014 Oliver Hahm <oliver.hahm@inria.fr>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_ng_rpl
 * @{
 * @file
 * @brief       Objective Function Zero.
 *
 * Implementation of Objective Function Zero.
 *
 * @author      Eric Engel <eric.engel@fu-berlin.de>
 * @}
 */

#include <string.h>
#include "of0.h"
#include "net/ng_rpl.h"
#include "net/ng_rpl/structs.h"

static uint16_t calc_rank(ng_rpl_parent_t *, uint16_t);
static ng_rpl_dodag_t *which_dodag(ng_rpl_dodag_t *, ng_rpl_dodag_t *);
static bool update_pref_parent(ng_rpl_dodag_t *dodag);

static ng_rpl_of_t ng_rpl_of0 = {
    0x0,
    calc_rank,
    which_dodag,
    update_pref_parent,
};

ng_rpl_of_t *ng_rpl_get_of0(void)
{
    return &ng_rpl_of0;
}

uint16_t calc_rank(ng_rpl_parent_t *parent, uint16_t base_rank)
{
    if (base_rank == 0) {
        if (parent == NULL) {
            return NG_RPL_INFINITE_RANK;
        }

        base_rank = parent->rank;
    }

    uint16_t add;

    if (parent != NULL) {
        add = parent->dodag->instance->min_hop_rank_inc;
    }
    else {
        add = NG_RPL_DEFAULT_MIN_HOP_RANK_INCREASE;
    }

    if ((base_rank + add) < base_rank) {
        return NG_RPL_INFINITE_RANK;
    }

    return base_rank + add;
}

bool update_pref_parent(ng_rpl_dodag_t *dodag)
{
    if (!dodag->parents) {
        return false;
    }

    uint16_t cur_min_path_cost = dodag->parents->rank;

    ng_rpl_parent_t *parent, *best;
    LL_FOREACH(dodag->parents, parent) {
        if (parent->rank < cur_min_path_cost) {
            if (best) {
                best = (parent->rank < best->rank) ? parent : best;
            }
            else {
                best = parent;
            }
        }
    }

    if (best && (best != dodag->parents)) {
        LL_DELETE(dodag->parents, best);
        LL_PREPEND(dodag->parents, best);
        return true;
    }

    return false;
}

/* Not used yet, as the implementation only makes use of one dodag for now. */
ng_rpl_dodag_t *which_dodag(ng_rpl_dodag_t *d1, ng_rpl_dodag_t *d2)
{
    (void) d2;
    return d1;
}
