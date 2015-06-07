/*
 * Copyright (C) 2013 Stephan Arndt <arndtste@zedat.fu-berlin.de>
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 */

#ifndef MRHOF_H
#define MRHOF_H

#include "net/ng_rpl.h"
#include "mrhof.h"
#include "utlist.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG
static char addr_str[NG_IPV6_ADDR_MAX_STR_LEN];
#endif

#ifdef __cplusplus
extern "C" {
#endif

static uint16_t calc_rank(ng_rpl_parent_t *, uint16_t);
static ng_rpl_dodag_t *which_dodag(ng_rpl_dodag_t *, ng_rpl_dodag_t *);
static uint16_t calc_path_cost(ng_rpl_parent_t *parent);
static bool update_pref_parent(ng_rpl_dodag_t *dodag);

static ng_rpl_of_t rpl_of_mrhof = {
    0x1,
    calc_rank,
    which_dodag,
    update_pref_parent,
};

ng_rpl_of_t *rpl_get_of_mrhof(void)
{
    return &rpl_of_mrhof;
}

static uint16_t calc_path_cost(ng_rpl_parent_t *parent)
{
    double etx_value = etx_get_metric(&(parent->addr));
    uint16_t cost = 0;

    if (etx_value != 0) {
        cost = (uint16_t) (etx_value * NG_RPL_ETX_RANK_MULTIPLIER + parent->rank);
        if ((cost > NG_RPL_MAX_LINK_METRIC) || (cost < parent->rank)) {
            return NG_RPL_MAX_PATH_COST;
        }

        return cost;
    }

    return NG_RPL_MAX_PATH_COST;
}

static uint16_t calc_rank(ng_rpl_parent_t *parent, uint16_t base_rank)
{
    (void) base_rank;
    uint16_t calculated_pcost = calc_path_cost(parent);
    uint16_t min_rank_inc = parent->rank + parent->dodag->instance->min_hop_rank_inc;

    if (calculated_pcost == NG_RPL_MAX_PATH_COST) {
        return NG_RPL_INFINITE_RANK;
    }

    return (calculated_pcost <= min_rank_inc) ? calculated_pcost : min_rank_inc;
}

bool update_pref_parent(ng_rpl_dodag_t *dodag)
{
    if (!dodag->parents) {
        return false;
    }

    uint16_t cur_min_path_cost = dodag->parents->rank;

    ng_rpl_parent_t *parent, *best;
    LL_FOREACH(dodag->parents, parent) {
        if ((parent->rank + NG_RPL_PARENT_SWITCH_THRESHOLD) < cur_min_path_cost) {
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

static ng_rpl_dodag_t *which_dodag(ng_rpl_dodag_t *d1, ng_rpl_dodag_t *d2)
{
    (void) d2;
    return d1;
}

#ifdef __cplusplus
}
#endif

#endif /* MRHOF_H */
/**
 * @}
 */
