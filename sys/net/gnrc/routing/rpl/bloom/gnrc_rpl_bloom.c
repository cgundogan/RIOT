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

#include "net/ipv6.h"
#include "net/gnrc/ipv6/netif.h"
#include "net/gnrc.h"
#include "hashes.h"
#include "bloom.h"

#include "net/gnrc/rpl.h"
#include "net/gnrc/rpl/dodag.h"
#include "net/gnrc/rpl/rpl_bloom.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG
static char addr_str[IPV6_ADDR_MAX_STR_LEN];
#endif

static hashfp_t _hashes[GNRC_RPL_BLOOM_HASHES_NUMOF] = {
    (hashfp_t) fnv_hash, (hashfp_t) sax_hash, (hashfp_t) sdbm_hash,
    (hashfp_t) djb2_hash, (hashfp_t) kr_hash, (hashfp_t) dek_hash,
    (hashfp_t) rotating_hash, (hashfp_t) one_at_a_time_hash
};

void gnrc_rpl_bloom_instance_nhood_init(gnrc_rpl_bloom_inst_ext_t *ext)
{
    ext->linksym_check_req = false;
    ext->bloom_refreshed_at = xtimer_now();
    memset(ext->bloom_buf, 0, sizeof(ext->bloom_buf));

    bloom_init(&(ext->nhood_bloom), GNRC_RPL_BLOOM_SIZE, ext->bloom_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);

    memset(ext->blacklist_bloom_buf, 0, sizeof(ext->blacklist_bloom_buf));
    bloom_init(&(ext->blacklist_bloom), GNRC_RPL_BLOOM_SIZE, ext->blacklist_bloom_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);
}

void gnrc_rpl_bloom_parent_nhood_init(gnrc_rpl_bloom_parent_ext_t *ext)
{
    ext->linksym_checks_req = 0;
    memset(ext->bloom_buf, 0, sizeof(ext->bloom_buf));

    bloom_init(&(ext->nhood_bloom), GNRC_RPL_BLOOM_SIZE, ext->bloom_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);
}

bool gnrc_rpl_bloom_add_neighbor(gnrc_rpl_bloom_inst_ext_t *ext, ipv6_addr_t *src,
                                 gnrc_rpl_opt_pa_t *pa)
{
    ipv6_addr_t parent = *src;
    uint8_t *parent_buf = (uint8_t *) (pa + 1);
    ipv6_addr_init_iid(&parent, parent_buf, IPV6_ADDR_BIT_LEN - pa->prefix_len);

    if (KERNEL_PID_UNDEF == (gnrc_ipv6_netif_find_by_addr(NULL, &parent))) {
        return false;
    }

    ipv6_addr_t src_suffix = *src;
    ipv6_addr_t src_prefix = IPV6_ADDR_UNSPECIFIED;
    ipv6_addr_init_prefix(&src_suffix, &src_prefix, pa->prefix_len);

    bloom_add(&(ext->nhood_bloom), (uint8_t *) &(src_suffix.u8[pa->prefix_len / 8]),
              (IPV6_ADDR_BIT_LEN - pa->prefix_len) / 8);

    ext->linksym_check_req = true;
    return true;
}

void gnrc_rpl_bloom_modify_rank(gnrc_rpl_bloom_parent_ext_t *ext)
{
    ipv6_addr_t *me;
    gnrc_ipv6_netif_find_by_prefix(&me, &(ext->parent->dodag->instance->dodag.dodag_id));

    if(!bloom_check(&(ext->nhood_bloom), (uint8_t *)me, sizeof(*me))) {
        ext->parent->rank |= GNRC_RPL_BLOOM_MSB;
    }
    else {
        ext->parent->rank &= ~GNRC_RPL_BLOOM_MSB;
    }
}

/**
 * @}
 */
