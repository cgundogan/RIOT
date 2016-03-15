/*
 * Copyright (C) 2016 Cenk Gündoğan <mail@cgundogan.de>
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
 * @author  Cenk Gündoğan <mail@cgundogan.de>
 */

#include "net/ipv6.h"
#include "net/gnrc/ipv6/netif.h"
#include "net/gnrc.h"
#include "hashes.h"
#include "bloom.h"

#include "net/gnrc/rpl/rpl_bloom.h"
#include "net/gnrc/rpl/structs.h"
#include "net/gnrc/rpl/dodag.h"

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

bloom_t gnrc_rpl_bloom_blacklist;
uint8_t gnrc_rpl_bloom_blacklist_buf[GNRC_RPL_BLACKLIST_BLOOM_SIZE];

static int _ipv6_addr_suffix(ipv6_addr_t *addr)
{
    ipv6_addr_t *me;
    uint8_t prefix_bits, prefix_bytes;
    /* find my address */
    gnrc_ipv6_netif_find_by_prefix(&me, addr);
    if (me == NULL) {
        DEBUG("RPL-BLOOM: no address configured\n");
        return -1;
    }

    /* how many bits are equal? convert to bytes (round down) */
    prefix_bits = ipv6_addr_match_prefix(me, addr);
    prefix_bytes = prefix_bits >> 3;
    /* unset unaligned bits in first byte */
    addr->u8[prefix_bytes] &= (0xFF >> (prefix_bits % 8));
    return prefix_bits;
}

void gnrc_rpl_bloom_init(void)
{
    memset(gnrc_rpl_bloom_blacklist_buf, 0, sizeof(gnrc_rpl_bloom_blacklist_buf));
    bloom_init(&(gnrc_rpl_bloom_blacklist), GNRC_RPL_BLOOM_SIZE, gnrc_rpl_bloom_blacklist_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);
}

void gnrc_rpl_bloom_instance_ext_init(gnrc_rpl_bloom_inst_ext_t *ext)
{
    ext->bloom_refreshed_at = xtimer_now();
    memset(ext->nhood_bloom_buf, 0, sizeof(ext->nhood_bloom_buf));

    bloom_init(&(ext->nhood_bloom), GNRC_RPL_BLOOM_SIZE, ext->nhood_bloom_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);
}

void gnrc_rpl_bloom_instance_ext_remove(gnrc_rpl_bloom_inst_ext_t *ext)
{
    memset(ext, 0, sizeof(gnrc_rpl_bloom_inst_ext_t));
}

void gnrc_rpl_bloom_parent_ext_init(gnrc_rpl_bloom_parent_ext_t *ext)
{
    ext->linksym_checks = 0;
    ext->link_check_msg.type = GNRC_RPL_BLOOM_MSG_TYPE_LINKSYM;
    ext->link_check_msg.content.ptr = (char *) ext;
    memset(ext->nhood_bloom_buf, 0, sizeof(ext->nhood_bloom_buf));

    bloom_init(&(ext->nhood_bloom), GNRC_RPL_BLOOM_SIZE, ext->nhood_bloom_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);
}

void gnrc_rpl_bloom_parent_ext_remove(gnrc_rpl_bloom_parent_ext_t *ext)
{
    xtimer_remove(&ext->link_check_timer);
    memset(ext, 0, sizeof(gnrc_rpl_bloom_parent_ext_t));
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

    ext->instance->dodag.dio_opts |= GNRC_RPL_REQ_OPT_NA;
    return true;
}

gnrc_pktsnip_t *gnrc_rpl_bloom_dis_pa_build(gnrc_pktsnip_t *pkt, gnrc_rpl_bloom_inst_ext_t *ext,
                                            ipv6_addr_t *dest)
{
    gnrc_rpl_opt_pa_t *opt_pa;
    gnrc_pktsnip_t *opt_snip;
    gnrc_rpl_parent_t *parent;

    bool stop = false;
    bool is_unicast = (dest && (!ipv6_addr_is_multicast(dest)));
    int prefix_bits;
    uint8_t prefix_bytes, addr_len;
    ipv6_addr_t paddr;
    LL_FOREACH(ext->instance->dodag.parents, parent) {

        if (is_unicast) {
           if (ipv6_addr_equal(dest, &parent->addr)) {
            stop = true;
           }
           else {
               continue;
           }
        }

        paddr = parent->addr;
        prefix_bits = _ipv6_addr_suffix(&paddr);
        if (prefix_bits < 0) {
            return NULL;
        }
        prefix_bytes = prefix_bits >> 3;
        addr_len = sizeof(ipv6_addr_t) - prefix_bytes;

        DEBUG("RPL-BLOOM: put (%s) into PA\n", ipv6_addr_to_str(addr_str, &paddr, sizeof(addr_str)));

        if ((opt_snip = gnrc_pktbuf_add(pkt, NULL, addr_len, GNRC_NETTYPE_UNDEF)) == NULL) {
            DEBUG("RPL-BLOOM: BUILD PARENT ANNOUNCEMENT OPT - no space left in packet buffer\n");
            gnrc_pktbuf_release(pkt);
            return NULL;
        }
        pkt = opt_snip;
        memcpy(pkt->data, &paddr.u8[prefix_bytes], addr_len);

        if ((opt_snip = gnrc_pktbuf_add(pkt, NULL, sizeof(gnrc_rpl_opt_pa_t),
                                        GNRC_NETTYPE_UNDEF)) == NULL) {
            DEBUG("RPL-BLOOM: BUILD PARENT ANNOUNCEMENT OPT - no space left in packet buffer\n");
            gnrc_pktbuf_release(pkt);
            return NULL;
        }
        pkt = opt_snip;

        opt_pa = pkt->data;
        opt_pa->type = GNRC_RPL_OPT_PARENT_ANNOUNCEMENT;
        opt_pa->length = sizeof(gnrc_rpl_opt_pa_t) - sizeof(gnrc_rpl_opt_t) + addr_len;
        opt_pa->prefix_len = prefix_bits;

        if (stop) {
            break;
        }
    }

    return pkt;
}

gnrc_pktsnip_t *gnrc_rpl_bloom_dio_na_build(gnrc_pktsnip_t *pkt, gnrc_rpl_bloom_inst_ext_t *ext)
{
    gnrc_rpl_opt_na_t *opt_na;
    gnrc_pktsnip_t *opt_snip;

    if ((opt_snip = gnrc_pktbuf_add(pkt, NULL, GNRC_RPL_BLOOM_SIZE, GNRC_NETTYPE_UNDEF)) == NULL) {
        DEBUG("RPL-BLOOM: BUILD NHOOD ANNOUNCEMENT OPT - no space left in packet buffer\n");
        gnrc_pktbuf_release(pkt);
        return NULL;
    }
    pkt = opt_snip;
    memcpy(pkt->data, ext->nhood_bloom_buf, GNRC_RPL_BLOOM_SIZE);

    if ((opt_snip = gnrc_pktbuf_add(pkt, NULL, sizeof(gnrc_rpl_opt_na_t),
                                    GNRC_NETTYPE_UNDEF)) == NULL) {
        DEBUG("RPL-BLOOM: BUILD NHOOD ANNOUNCEMENT OPT - no space left in packet buffer\n");
        gnrc_pktbuf_release(pkt);
        return NULL;
    }
    pkt = opt_snip;

    opt_na = pkt->data;
    opt_na->type = GNRC_RPL_OPT_NHOOD_ANNOUNCEMENT;
    opt_na->length = sizeof(gnrc_rpl_opt_na_t) - sizeof(gnrc_rpl_opt_t) + GNRC_RPL_BLOOM_SIZE;

    return pkt;
}

void gnrc_rpl_bloom_request_na(gnrc_rpl_bloom_parent_ext_t *ext)
{
    gnrc_rpl_parent_t *tmp = NULL;
    gnrc_rpl_dodag_t *dodag;
    bool has_bidir_link = false;

    if ((ext->parent == NULL) || (ext->parent->state == 0)) {
        DEBUG("RPL-BLOOM: no parent specified\n");
        return;
    }

    if (ext->bidirectional) {
        return;
    }

    dodag = ext->parent->dodag;

    if ((++ext->linksym_checks) > GNRC_RPL_BLOOM_LINKSYM_RETRIES) {
        bloom_add(&gnrc_rpl_bloom_blacklist, ext->parent->addr.u8, sizeof(ipv6_addr_t));
        DEBUG("RPL-BLOOM: blacklisted %s\n", ipv6_addr_to_str(addr_str, &ext->parent->addr,
                                             sizeof(addr_str)));
        gnrc_rpl_parent_remove(ext->parent);
        gnrc_rpl_parent_update(dodag, NULL);
        return;
    }

    dodag->dis_opts |= GNRC_RPL_REQ_DIS_OPT_PA;
    uint8_t req_na[1] = { GNRC_RPL_OPT_NHOOD_ANNOUNCEMENT };
    gnrc_rpl_send_DIS(dodag->instance, &ext->parent->addr, 0, req_na, 1);
    xtimer_set_msg(&ext->link_check_timer,
                   GNRC_RPL_BLOOM_LINKSYM_RETRY_INTERVAL * SEC_IN_USEC,
                   &ext->link_check_msg, gnrc_rpl_pid);
}

void gnrc_rpl_bloom_handle_pa(gnrc_rpl_opt_pa_t *opt, ipv6_addr_t *src, gnrc_rpl_instance_t *inst,
                              uint32_t *included_opts)
{
    DEBUG("RPL-BLOOM: PARENT ANNOUNCEMENT option parsed\n");
    ipv6_addr_t me = *src;
    uint8_t *suffix = ((uint8_t *) opt) + sizeof(*opt);
    *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_PARENT_ANNOUNCEMENT;
    ipv6_addr_init_iid(&me, suffix, IPV6_ADDR_BIT_LEN - opt->prefix_len);
    if (gnrc_ipv6_netif_find_by_addr(NULL, &me) != KERNEL_PID_UNDEF) {
        DEBUG("RPL-BLOOM: add (%s) to bloom\n",
              ipv6_addr_to_str(addr_str, src, sizeof(addr_str)));
        bloom_add(&(inst->bloom_ext.nhood_bloom), src->u8, sizeof(ipv6_addr_t));
    }
}

void gnrc_rpl_bloom_handle_na(gnrc_rpl_opt_na_t *opt, ipv6_addr_t *src, gnrc_rpl_instance_t *inst,
                              uint32_t *included_opts)
{
    DEBUG("RPL-BLOOM: NHOOD ANNOUNCEMENT option parsed\n");
    gnrc_rpl_parent_t *parent;
    ipv6_addr_t paddr;
    int prefix_bits;
    uint8_t prefix_bytes, addr_len;
    LL_FOREACH(inst->dodag.parents, parent) {
        if (ipv6_addr_equal(src, &parent->addr)) {
            memcpy(parent->bloom_ext.nhood_bloom_buf,
                   ((uint8_t *) opt) + sizeof(gnrc_rpl_opt_t), opt->length);
            *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_PARENT_ANNOUNCEMENT;

            paddr = *src;
            prefix_bits = _ipv6_addr_suffix(&paddr);
            if (prefix_bits < 0) {
                return;
            }
            prefix_bytes = prefix_bits >> 3;
            addr_len = sizeof(ipv6_addr_t) - prefix_bytes;
            if (bloom_check(&parent->bloom_ext.nhood_bloom, &paddr.u8[prefix_bytes], addr_len)) {
                DEBUG("RPL-BLOOM: bidirectional link with (%s)\n",
                      ipv6_addr_to_str(addr_str, src, sizeof(addr_str)));
                parent->bloom_ext.bidirectional = true;
            }
            break;
        }
    }
}

/**
 * @}
 */
