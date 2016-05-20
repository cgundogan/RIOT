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
#include "random.h"

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
msg_t gnrc_rpl_bloom_blacklist_msg;
xtimer_t gnrc_rpl_bloom_blacklist_timer;

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
    gnrc_rpl_bloom_blacklist_msg.type = GNRC_RPL_BLOOM_MSG_TYPE_BLACKLIST;
    gnrc_rpl_bloom_blacklist_reset();
    bloom_init(&(gnrc_rpl_bloom_blacklist), GNRC_RPL_BLOOM_SIZE, gnrc_rpl_bloom_blacklist_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);
}

void gnrc_rpl_bloom_blacklist_reset(void)
{
    DEBUG("RPL-BLOOM: reseting blacklist bloom filter\n");
    memset(gnrc_rpl_bloom_blacklist_buf, 0,
           sizeof(gnrc_rpl_bloom_blacklist_buf)/sizeof(gnrc_rpl_bloom_blacklist_buf[0]));
    xtimer_set_msg(&gnrc_rpl_bloom_blacklist_timer,
                   (GNRC_RPL_BLOOM_BLACKLIST_LIFETIME + random_uint32_range(0, 10)) * SEC_IN_USEC,
                   &gnrc_rpl_bloom_blacklist_msg, gnrc_rpl_pid);
}

void gnrc_rpl_bloom_instance_ext_init(gnrc_rpl_bloom_inst_ext_t *ext)
{
    gnrc_rpl_bloom_refresh(ext);
    ext->na_req_running = false;
    ext->link_check_msg.type = GNRC_RPL_BLOOM_MSG_TYPE_LINKSYM;
    ext->link_check_msg.content.ptr = (char *) ext;
    ext->dio_msg.type = GNRC_RPL_BLOOM_MSG_TYPE_DELAYED_DIO;
    ext->dio_msg.content.ptr = (char *) ext;
    ext->delayed_dio = false;
    bloom_init(&(ext->nhood_bloom), GNRC_RPL_BLOOM_SIZE, ext->nhood_bloom_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);
}

void gnrc_rpl_bloom_refresh(gnrc_rpl_bloom_inst_ext_t *ext)
{
    DEBUG("RPL-BLOOM: reseting neighborhood bloom filter\n");
    memset(ext->nhood_bloom_buf, 0, sizeof(ext->nhood_bloom_buf));
    ext->bloom_lifetime = GNRC_RPL_BLOOM_LIFETIME + random_uint32_range(0, 10);
}

void gnrc_rpl_bloom_instance_ext_remove(gnrc_rpl_bloom_inst_ext_t *ext)
{
    xtimer_remove(&ext->link_check_timer);
    xtimer_remove(&ext->dio_timer);
    memset(ext, 0, sizeof(gnrc_rpl_bloom_inst_ext_t));
}

void gnrc_rpl_bloom_parent_ext_init(gnrc_rpl_bloom_parent_ext_t *ext)
{
    ext->bidirectional = false;
    ext->linksym_checks = 0;
    memset(ext->nhood_bloom_buf, 0, sizeof(ext->nhood_bloom_buf));
    bloom_init(&(ext->nhood_bloom), GNRC_RPL_BLOOM_SIZE, ext->nhood_bloom_buf,
               _hashes, GNRC_RPL_BLOOM_HASHES_NUMOF);
}

void gnrc_rpl_bloom_parent_ext_remove(gnrc_rpl_bloom_parent_ext_t *ext)
{
    memset(ext, 0, sizeof(gnrc_rpl_bloom_parent_ext_t));
}

static gnrc_pktsnip_t *_handle_parents_dis_pa_build(gnrc_pktsnip_t *pkt, gnrc_rpl_parent_t *parent)
{
    gnrc_rpl_opt_pa_t *opt_pa;
    gnrc_pktsnip_t *opt_snip;

    int prefix_bits;
    uint8_t prefix_bytes, addr_len;
    ipv6_addr_t paddr;

    paddr = parent->addr;
    prefix_bits = _ipv6_addr_suffix(&paddr);
    if (prefix_bits < 0) {
        DEBUG("RPL-BLOOM: BUILD PARENT ANNOUNCEMENT OPT - prefix bits negative\n");
        gnrc_pktbuf_release(pkt);
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
    memcpy((pkt)->data, &paddr.u8[prefix_bytes], addr_len);

    if ((opt_snip = gnrc_pktbuf_add(pkt, NULL, sizeof(gnrc_rpl_opt_pa_t),
                                    GNRC_NETTYPE_UNDEF)) == NULL) {
        DEBUG("RPL-BLOOM: BUILD PARENT ANNOUNCEMENT OPT - no space left in packet buffer\n");
        gnrc_pktbuf_release(pkt);
        return NULL;
    }
    pkt = opt_snip;

    opt_pa = (pkt)->data;
    opt_pa->type = GNRC_RPL_OPT_PARENT_ANNOUNCEMENT;
    opt_pa->length = sizeof(gnrc_rpl_opt_pa_t) - sizeof(gnrc_rpl_opt_t) + addr_len;
    opt_pa->prefix_len = prefix_bits;

    return pkt;
}

gnrc_pktsnip_t *gnrc_rpl_bloom_dis_pa_build(gnrc_pktsnip_t *pkt, gnrc_rpl_bloom_inst_ext_t *ext,
                                            ipv6_addr_t *dest)
{
    gnrc_rpl_parent_t *parent;
    bool stop = false, is_unicast = (dest && (!ipv6_addr_is_multicast(dest)));
    gnrc_pktsnip_t *tmp;

    LL_FOREACH(ext->instance->dodag.parents, parent) {
        if (parent->bloom_ext.bidirectional) {
            continue;
        }

        if (is_unicast) {
            if (ipv6_addr_equal(dest, &parent->addr)) {
                stop = true;
            }
            else {
                continue;
            }
        }

        if ((tmp = _handle_parents_dis_pa_build(pkt, parent)) == NULL) {
            gnrc_pktbuf_release(pkt);
            return NULL;
        }
        pkt = tmp;

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

void gnrc_rpl_bloom_request_na(gnrc_rpl_bloom_inst_ext_t *ext, bool dio)
{
    assert(ext->instance && ext->instance->state);
    gnrc_rpl_dodag_t *dodag = &ext->instance->dodag;
    gnrc_rpl_parent_t *parent;
    bool unchecked_parents = false, checked_parents = false;

    LL_FOREACH(dodag->parents, parent) {
        gnrc_rpl_bloom_parent_ext_t *pext = &parent->bloom_ext;

        if (parent->bloom_ext.bidirectional) {
            checked_parents = true;
            continue;
        }

        if (++pext->linksym_checks > GNRC_RPL_BLOOM_LINKSYM_RETRIES) {
            bloom_add(&gnrc_rpl_bloom_blacklist, pext->parent->addr.u8, sizeof(ipv6_addr_t));
            DEBUG("RPL-BLOOM: blacklisted %s\n", ipv6_addr_to_str(addr_str, &pext->parent->addr,
                                                                  sizeof(addr_str)));
            gnrc_rpl_parent_remove(pext->parent);
            gnrc_rpl_parent_update(dodag, NULL);
            continue;
        }
        else {
            unchecked_parents = true;
            if (!dio) {
                DEBUG("RPL-BLOOM: requesting NA\n");
                //dodag->dis_opts |= GNRC_RPL_REQ_OPT_PA;
                uint8_t req_na[1] = { GNRC_RPL_OPT_NHOOD_ANNOUNCEMENT };
                gnrc_rpl_send_DIS(dodag->instance, &parent->addr, 0, req_na, sizeof(req_na)/sizeof(req_na[0]));
            }
        }
    }

    if (unchecked_parents) {
        ext->na_req_running = true;
        if (dio) {
            DEBUG("RPL-BLOOM: requesting NA\n");
            dodag->dio_opts |= GNRC_RPL_REQ_OPT_PA;
            uint8_t req_na[1] = { GNRC_RPL_OPT_NHOOD_ANNOUNCEMENT };
            printf("Send DIO with PAs\n");
            gnrc_rpl_send_DIO(dodag->instance,(ipv6_addr_t *) &ipv6_addr_all_rpl_nodes, req_na,
                              sizeof(req_na)/sizeof(req_na[0]));
        }
        xtimer_set_msg(&ext->link_check_timer, GNRC_RPL_BLOOM_LINKSYM_RETRY_INTERVAL *
                       SEC_IN_USEC + random_uint32_range(SEC_IN_MS * 50, SEC_IN_MS * 1000),
                       &ext->link_check_msg, gnrc_rpl_pid);
    }
    else {
        ext->na_req_running = false;
        xtimer_remove(&ext->link_check_timer);
    }

    if (!checked_parents) {
        dodag->node_status = GNRC_RPL_LEAF_NODE;
    }
}

void gnrc_rpl_bloom_handle_pa(gnrc_rpl_opt_pa_t *opt, ipv6_addr_t *src,
                              gnrc_rpl_bloom_inst_ext_t *ext, uint32_t *included_opts)
{
    DEBUG("RPL-BLOOM: PARENT ANNOUNCEMENT option parsed\n");
    ipv6_addr_t me = *src;
    uint8_t *suffix = ((uint8_t *) opt) + sizeof(*opt);

    *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_PARENT_ANNOUNCEMENT;
    ipv6_addr_init_iid(&me, suffix, IPV6_ADDR_BIT_LEN - opt->prefix_len);
    if (gnrc_ipv6_netif_find_by_addr(NULL, &me) != KERNEL_PID_UNDEF) {
        DEBUG("RPL-BLOOM: add (%s) to neighborhood bloom\n",
              ipv6_addr_to_str(addr_str, &src_tmp, sizeof(addr_str)));
        gnrc_rpl_bloom_add(ext, src->u8, sizeof(ipv6_addr_t));
    }
}

void gnrc_rpl_bloom_handle_na(gnrc_rpl_opt_na_t *opt, ipv6_addr_t *src,
                              gnrc_rpl_bloom_inst_ext_t *ext, uint32_t *included_opts)
{
    DEBUG("RPL-BLOOM: NHOOD ANNOUNCEMENT option parsed\n");
    assert(ext && ext->instance);

    gnrc_rpl_parent_t *parent;
    gnrc_rpl_dodag_t *dodag = &ext->instance->dodag;
    ipv6_addr_t *me = NULL;

    LL_FOREACH(dodag->parents, parent) {
        if (ipv6_addr_equal(src, &parent->addr)) {
            break;
        }
    }

    if (parent) {
        memcpy(parent->bloom_ext.nhood_bloom_buf,
               ((uint8_t *) opt) + sizeof(gnrc_rpl_opt_na_t), opt->length);
        *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_PARENT_ANNOUNCEMENT;

        if (gnrc_ipv6_netif_find_by_prefix(&me, src) != KERNEL_PID_UNDEF) {
            DEBUG("checking: %s\n", ipv6_addr_to_str(addr_str, me, sizeof(addr_str)));
            if (bloom_check(&parent->bloom_ext.nhood_bloom, me->u8, sizeof(ipv6_addr_t))) {
                if (!parent->bloom_ext.bidirectional) {
                    DEBUG("RPL-BLOOM: bidirectional link with (%s)\n",
                          ipv6_addr_to_str(addr_str, src, sizeof(addr_str)));

                    parent->bloom_ext.bidirectional = true;
                    parent->bloom_ext.linksym_checks = 0;
                    gnrc_rpl_parent_update(dodag, parent);
                }
            }
            else {
                DEBUG("RPL-BLOOM: my address not found in parent's nhood bloom filter\n");
                if (parent->bloom_ext.bidirectional) {
                    parent->bloom_ext.bidirectional = false;
                    gnrc_rpl_parent_update(dodag, NULL);
                }
                gnrc_rpl_bloom_request_na_safe(ext, false);
            }
            if ((dodag->node_status == GNRC_RPL_LEAF_NODE) && dodag->parents->bloom_ext.bidirectional) {
                dodag->node_status = GNRC_RPL_NORMAL_NODE;
                trickle_interval(&dodag->trickle);
            }
        }
    }
}

void gnrc_rpl_bloom_add(gnrc_rpl_bloom_inst_ext_t *ext, uint8_t *data, size_t len)
{
    bloom_add(&(ext->nhood_bloom), data, len);
    return;
}

bool gnrc_rpl_bloom_check_blacklist(ipv6_addr_t *addr)
{
    if (bloom_check(&(gnrc_rpl_bloom_blacklist), addr->u8, sizeof(ipv6_addr_t))) {
        DEBUG("RPL-BLOOM: (%s) is blacklisted\n", ipv6_addr_to_str(addr_str, addr, sizeof(addr_str)));
        return true;
    }
    return false;
}

bool gnrc_rpl_bloom_parse_options(gnrc_rpl_bloom_inst_ext_t *ext, uint8_t *opt, uint16_t len,
                                  ipv6_addr_t *src, uint32_t *included_opts)
{
    uint16_t l = 0;
    *included_opts = 0;

    while(l < len) {
        switch(opt[0]) {
            case (GNRC_RPL_OPT_PAD1):
                DEBUG("RPL: PAD1 option parsed\n");
                *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_PAD1;
                l += 1;
                opt += 2;
                continue;

            case (GNRC_RPL_OPT_PARENT_ANNOUNCEMENT):
                gnrc_rpl_bloom_handle_pa((gnrc_rpl_opt_pa_t *) opt, src, ext, included_opts);
                break;

            case (GNRC_RPL_OPT_NHOOD_ANNOUNCEMENT):
                gnrc_rpl_bloom_handle_na((gnrc_rpl_opt_na_t *) opt, src, ext, included_opts);
                break;

        }
        l += opt[1] + 2;
        opt += opt[1] + 2;
    }
    return true;
}

/**
 * @}
 */
