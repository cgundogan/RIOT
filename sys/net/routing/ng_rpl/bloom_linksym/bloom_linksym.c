/*
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
 *
 * @author  Cenk Gündoğan <cnkgndgn@gmail.com>
 */
#include "net/ng_rpl/ng_rpl_bloom.h"
#include "net/ng_ipv6.h"
#include "hashes.h"
#include "bloom.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"


void ng_rpl_bloom_linksym_neighborhood(ng_rpl_dodag_t *dodag)
{
#ifndef MODULE_NG_RPL_BLOOM_LINKSYM
    (void) dodag;
#else
    dodag->nhood_linksym = bloom_new(NG_RPL_BLOOM_LINKSYM_SIZE, 8, fnv_hash, sax_hash,
            sdbm_hash, djb2_hash, kr_hash, dek_hash, rotating_hash, one_at_a_time_hash);
#endif
}

bool ng_rpl_bloom_linksym_add_neighbor(ng_rpl_dodag_t *dodag, ng_ipv6_addr_t *src,
                                ng_rpl_opt_parent_announcement_t *pa)
{
#ifndef MODULE_NG_RPL_BLOOM_LINKSYM
    (void) dodag;
    (void) src;
    (void) pa;
    return false;
#else
    if (KERNEL_PID_UNDEF == (ng_ipv6_netif_find_by_addr(NULL, &pa->parent))) {
        return false;
    }
    bloom_add(dodag->nhood_linksym, (uint8_t *)src, sizeof(*src));
    dodag->linksym_check_requested = true;
    return true;
#endif
}

/**
 * @}
 */
