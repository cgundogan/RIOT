/*
 * Copyright (C) 2013 - 2014  INRIA.
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @{
 *
 * @file
 *
 * @author  Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#include "net/af.h"
#include "net/icmpv6.h"
#include "net/ipv6/hdr.h"
#include "net/gnrc/icmpv6.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc.h"
#include "net/eui64.h"

#include "net/gnrc/rpl.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG
static char addr_str[IPV6_ADDR_MAX_STR_LEN];
#endif

#define GNRC_RPL_GROUNDED_SHIFT             (7)
#define GNRC_RPL_MOP_SHIFT                  (3)
#define GNRC_RPL_OPT_DODAG_CONF_LEN         (14)
#define GNRC_RPL_OPT_PREFIX_INFO_LEN        (30)
#define GNRC_RPL_OPT_TARGET_LEN             (18)
#define GNRC_RPL_OPT_TRANSIT_INFO_LEN       (4)
#define GNRC_RPL_SHIFTED_MOP_MASK           (0x7)
#define GNRC_RPL_PRF_MASK                   (0x7)
#define GNRC_RPL_PREFIX_AUTO_ADDRESS_BIT    (1 << 6)
#define GNRC_RPL_DAO_D_BIT                  (1 << 6)
#define GNRC_RPL_DAO_K_BIT                  (1 << 7)
#define GNRC_RPL_DAO_ACK_D_BIT              (1 << 7)

void gnrc_rpl_send(gnrc_pktsnip_t *pkt, ipv6_addr_t *src, ipv6_addr_t *dst, ipv6_addr_t *dodag_id)
{
    gnrc_pktsnip_t *hdr;
    ipv6_addr_t all_RPL_nodes = GNRC_RPL_ALL_NODES_ADDR, ll_addr;
    kernel_pid_t iface = gnrc_ipv6_netif_find_by_addr(NULL, &all_RPL_nodes);
    if (iface == KERNEL_PID_UNDEF) {
        DEBUG("RPL: no suitable interface found for this destination address\n");
        gnrc_pktbuf_release(pkt);
        return;
    }

    if (src == NULL) {
        ipv6_addr_t *tmp = NULL;
        if (dodag_id != NULL) {
            tmp = gnrc_ipv6_netif_match_prefix(iface, dodag_id);
        }
        else if (dodag_id == NULL) {
            tmp = gnrc_ipv6_netif_find_best_src_addr(iface, &all_RPL_nodes);
        }

        if (tmp == NULL) {
            DEBUG("RPL: no suitable src address found\n");
            gnrc_pktbuf_release(pkt);
            return;
        }

        memcpy(&ll_addr, tmp, sizeof(ll_addr));
        ipv6_addr_set_link_local_prefix(&ll_addr);
        src = &ll_addr;
    }

    if (dst == NULL) {
        dst = &all_RPL_nodes;
    }

    hdr = gnrc_ipv6_hdr_build(pkt, (uint8_t *)src, sizeof(ipv6_addr_t), (uint8_t *)dst,
                            sizeof(ipv6_addr_t));

    if (hdr == NULL) {
        DEBUG("RPL: Send - no space left in packet buffer\n");
        gnrc_pktbuf_release(pkt);
        return;
    }

    if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_IPV6, GNRC_NETREG_DEMUX_CTX_ALL,hdr)) {
        DEBUG("RPL: cannot send packet: no subscribers found.\n");
        gnrc_pktbuf_release(hdr);
    }

}

void gnrc_rpl_send_DIO(gnrc_rpl_instance_t *inst, ipv6_addr_t *destination)
{
    if (inst == NULL) {
        DEBUG("RPL: Error - trying to send DIO without being part of a dodag.\n");
        return;
    }

    gnrc_pktsnip_t *pkt;
    icmpv6_hdr_t *icmp;
    gnrc_rpl_dio_t *dio;
    uint8_t *pos;
    int size = sizeof(icmpv6_hdr_t) + sizeof(gnrc_rpl_dio_t);

    if (inst->dodag.dodag_conf_requested) {
        size += sizeof(gnrc_rpl_opt_dodag_conf_t);
    }

    if (inst->dodag.prefix_info_requested) {
        size += sizeof(gnrc_rpl_opt_prefix_info_t);
    }

    if ((pkt = gnrc_icmpv6_build(NULL, ICMPV6_RPL_CTRL, GNRC_RPL_ICMPV6_CODE_DIO, size)) == NULL) {
        DEBUG("RPL: Send DIO - no space left in packet buffer\n");
        return;
    }

    icmp = (icmpv6_hdr_t *)pkt->data;
    dio = (gnrc_rpl_dio_t *)(icmp + 1);
    pos = (uint8_t *) dio;
    dio->instance_id = inst->id;
    dio->version_number = inst->dodag.version;
    dio->rank = byteorder_htons(inst->dodag.my_rank);
    dio->g_mop_prf = (inst->dodag.grounded << GNRC_RPL_GROUNDED_SHIFT) |
        (inst->mop << GNRC_RPL_MOP_SHIFT) | inst->dodag.prf;
    dio->dtsn = inst->dodag.dtsn;
    dio->flags = 0;
    dio->reserved = 0;
    dio->dodag_id = inst->dodag.dodag_id;

    pos += sizeof(*dio);

    if (inst->dodag.dodag_conf_requested) {
        gnrc_rpl_opt_dodag_conf_t *dodag_conf;
        dodag_conf = (gnrc_rpl_opt_dodag_conf_t *) pos;
        dodag_conf->type = GNRC_RPL_OPT_DODAG_CONF;
        dodag_conf->length = GNRC_RPL_OPT_DODAG_CONF_LEN;
        dodag_conf->flags_a_pcs = 0;
        dodag_conf->dio_int_doubl = inst->dodag.dio_interval_doubl;
        dodag_conf->dio_int_min = inst->dodag.dio_min;
        dodag_conf->dio_redun = inst->dodag.dio_redun;
        dodag_conf->max_rank_inc = byteorder_htons(inst->max_rank_inc);
        dodag_conf->min_hop_rank_inc = byteorder_htons(inst->min_hop_rank_inc);
        dodag_conf->ocp = byteorder_htons(inst->of->ocp);
        dodag_conf->reserved = 0;
        dodag_conf->default_lifetime = inst->dodag.default_lifetime;
        dodag_conf->lifetime_unit = byteorder_htons(inst->dodag.lifetime_unit);
        pos += sizeof(*dodag_conf);
        inst->dodag.dodag_conf_requested = false;
    }

    if (inst->dodag.prefix_info_requested) {
        gnrc_rpl_opt_prefix_info_t *prefix_info;
        prefix_info = (gnrc_rpl_opt_prefix_info_t *) pos;
        prefix_info->type = GNRC_RPL_OPT_PREFIX_INFO;
        prefix_info->length = GNRC_RPL_OPT_PREFIX_INFO_LEN;
        /* auto-address configuration */
        prefix_info->LAR_flags = GNRC_RPL_PREFIX_AUTO_ADDRESS_BIT;
        prefix_info->valid_lifetime = inst->dodag.addr_valid;
        prefix_info->pref_lifetime = inst->dodag.addr_preferred;
        prefix_info->prefix_len = inst->dodag.prefix_len;
        prefix_info->reserved = 0;

        memset(&prefix_info->prefix, 0, sizeof(prefix_info->prefix));
        ipv6_addr_init_prefix(&prefix_info->prefix, &(inst->dodag.dodag_id),
                              inst->dodag.prefix_len);
        inst->dodag.prefix_info_requested = false;
    }

    gnrc_rpl_send(pkt, NULL, destination, &(inst->dodag.dodag_id));
}

void gnrc_rpl_send_DIS(gnrc_rpl_instance_t *inst, ipv6_addr_t *destination)
{
    gnrc_pktsnip_t *pkt;
    icmpv6_hdr_t *icmp;
    gnrc_rpl_dis_t *dis;
    /* TODO: Currently the DIS is too small so that wireshark complains about an incorrect
     * ethernet frame check sequence. In order to prevent this, 4 PAD1 options are added.
     * This will be addressed in follow-up PRs */
    int size = sizeof(icmpv6_hdr_t) + sizeof(gnrc_rpl_dis_t) + 4;

    if ((pkt = gnrc_icmpv6_build(NULL, ICMPV6_RPL_CTRL, GNRC_RPL_ICMPV6_CODE_DIS, size)) == NULL) {
        DEBUG("RPL: Send DIS - no space left in packet buffer\n");
        return;
    }

    icmp = (icmpv6_hdr_t *)pkt->data;
    dis = (gnrc_rpl_dis_t *)(icmp + 1);
    dis->flags = 0;
    dis->reserved = 0;
    /* TODO: see above TODO */
    memset((dis + 1), 0, 4);

    gnrc_rpl_send(pkt, NULL, destination, (inst? &(inst->dodag.dodag_id) : NULL));
}

static bool _gnrc_rpl_check_DIS_validity(gnrc_rpl_dis_t *dis, uint16_t len)
{
    uint16_t expected_len = sizeof(*dis) + sizeof(icmpv6_hdr_t);

    if (expected_len <= len) {
        return true;
    }

    DEBUG("RPL: wrong DIS len: %d, expected: %d\n", len, expected_len);

    return false;
}

void gnrc_rpl_recv_DIS(gnrc_rpl_dis_t *dis, ipv6_addr_t *src, ipv6_addr_t *dst, uint16_t len)
{
    /* TODO handle Solicited Information Option */
    (void) dis;
    (void) len;

    if (!_gnrc_rpl_check_DIS_validity(dis, len)) {
        return;
    }

    if (ipv6_addr_is_multicast(dst)) {
        for (uint8_t i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
            if (gnrc_rpl_instances[i].state != 0) {
                trickle_reset_timer(&(gnrc_rpl_instances[i].dodag.trickle));
            }
        }
    }
    else {
        for (uint8_t i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
            if (gnrc_rpl_instances[i].state != 0) {
                gnrc_rpl_instances[i].dodag.dodag_conf_requested = true;
                gnrc_rpl_instances[i].dodag.prefix_info_requested = true;
                gnrc_rpl_send_DIO(&gnrc_rpl_instances[i], src);
            }
        }
    }
}

static bool _gnrc_rpl_check_options_validity(int msg_type, gnrc_rpl_instance_t *inst,
                                                gnrc_rpl_opt_t *opt, uint16_t len)
{
    uint16_t expected_len = 0;

    while(expected_len < len) {
        switch(opt->type) {
            case (GNRC_RPL_OPT_PAD1):
                expected_len += 1;
                opt = (gnrc_rpl_opt_t *) (((uint8_t *) opt) + 1);
                continue;

            case (GNRC_RPL_OPT_DODAG_CONF):
                if (msg_type != GNRC_RPL_ICMPV6_CODE_DIO) {
                    DEBUG("RPL: DODAG CONF DIO option not expected\n");
                    return false;
                }

                if (opt->length != GNRC_RPL_OPT_DODAG_CONF_LEN) {
                    DEBUG("RPL: wrong DIO option (DODAG CONF) len: %d, expected: %d\n",
                            opt->length, GNRC_RPL_OPT_DODAG_CONF_LEN);
                    return false;
                }
                break;

            case (GNRC_RPL_OPT_PREFIX_INFO):
                if (msg_type != GNRC_RPL_ICMPV6_CODE_DIO) {
                    DEBUG("RPL: PREFIX INFO DIO option not expected\n");
                    return false;
                }

                if (opt->length != GNRC_RPL_OPT_PREFIX_INFO_LEN) {
                    DEBUG("RPL: wrong DIO option (PREFIX INFO) len: %d, expected: %d\n",
                            opt->length, GNRC_RPL_OPT_PREFIX_INFO_LEN);
                    return false;
                }
                break;

            case (GNRC_RPL_OPT_TARGET):
                if (msg_type != GNRC_RPL_ICMPV6_CODE_DAO) {
                    DEBUG("RPL: RPL TARGET DAO option not expected\n");
                    return false;
                }

                if (opt->length > GNRC_RPL_OPT_TARGET_LEN) {
                    DEBUG("RPL: wrong DAO option (RPL TARGET) len: %d, expected (max): %d\n",
                            opt->length, GNRC_RPL_OPT_TARGET_LEN);
                    return false;
                }
                break;

            case (GNRC_RPL_OPT_TRANSIT):
                if (msg_type != GNRC_RPL_ICMPV6_CODE_DAO) {
                    DEBUG("RPL: RPL TRANSIT INFO DAO option not expected\n");
                    return false;
                }

                uint8_t parent_addr = 0;
                if (inst->mop == GNRC_RPL_MOP_NON_STORING_MODE) {
                    parent_addr = sizeof(ipv6_addr_t);
                }

                if (opt->length != (GNRC_RPL_OPT_TRANSIT_INFO_LEN + parent_addr)) {
                    DEBUG("RPL: wrong DAO option (TRANSIT INFO) len: %d, expected: %d\n",
                            opt->length, (GNRC_RPL_OPT_TRANSIT_INFO_LEN + parent_addr));
                    return false;
                }
                break;

            default:
                break;

        }
        expected_len += opt->length + sizeof(gnrc_rpl_opt_t);
        opt = (gnrc_rpl_opt_t *) (((uint8_t *) (opt + 1)) + opt->length);
    }

    if (expected_len == len) {
        return true;
    }

    DEBUG("RPL: wrong options len: %d, expected: %d\n", len, expected_len);

    return false;
}

/** @todo allow target prefixes in target options to be of variable length */
bool _parse_options(int msg_type, gnrc_rpl_instance_t *inst, gnrc_rpl_opt_t *opt, uint16_t len,
                    ipv6_addr_t *src, uint32_t *included_opts)
{
    uint16_t l = 0;
    gnrc_rpl_opt_target_t *first_target = NULL;
    eui64_t iid;
    kernel_pid_t if_id = KERNEL_PID_UNDEF;
    *included_opts = 0;

    if (!_gnrc_rpl_check_options_validity(msg_type, inst, opt, len)) {
        return false;
    }

    while(l < len) {
        switch(opt->type) {
            case (GNRC_RPL_OPT_PAD1):
                DEBUG("RPL: PAD1 option parsed\n");
                *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_PAD1;
                l += 1;
                opt = (gnrc_rpl_opt_t *) (((uint8_t *) opt) + 1);
                continue;

            case (GNRC_RPL_OPT_PADN):
                DEBUG("RPL: PADN option parsed\n");
                *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_PADN;
                break;

            case (GNRC_RPL_OPT_DODAG_CONF):
                DEBUG("RPL: DODAG CONF DIO option parsed\n");
                *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_DODAG_CONF;
                inst->dodag.dodag_conf_requested = true;
                gnrc_rpl_opt_dodag_conf_t *dc = (gnrc_rpl_opt_dodag_conf_t *) opt;
                gnrc_rpl_of_t *of = gnrc_rpl_get_of_for_ocp(byteorder_ntohs(dc->ocp));
                if (of != NULL) {
                    inst->of = of;
                }
                else {
                    DEBUG("RPL: Unsupported OCP 0x%02x\n", byteorder_ntohs(dc->ocp));
                    inst->of = gnrc_rpl_get_of_for_ocp(GNRC_RPL_DEFAULT_OCP);
                }
                inst->dodag.dio_interval_doubl = dc->dio_int_doubl;
                inst->dodag.dio_min = dc->dio_int_min;
                inst->dodag.dio_redun = dc->dio_redun;
                inst->max_rank_inc = byteorder_ntohs(dc->max_rank_inc);
                inst->min_hop_rank_inc = byteorder_ntohs(dc->min_hop_rank_inc);
                inst->dodag.default_lifetime = dc->default_lifetime;
                inst->dodag.lifetime_unit = byteorder_ntohs(dc->lifetime_unit);
                inst->dodag.trickle.Imin = (1 << inst->dodag.dio_min);
                inst->dodag.trickle.Imax = inst->dodag.dio_interval_doubl;
                inst->dodag.trickle.k = inst->dodag.dio_redun;
                break;

            case (GNRC_RPL_OPT_PREFIX_INFO):
                DEBUG("RPL: Prefix Information DIO option parsed\n");
                *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_PREFIX_INFO;
                inst->dodag.prefix_info_requested = true;
                gnrc_rpl_opt_prefix_info_t *pi = (gnrc_rpl_opt_prefix_info_t *) opt;
                ipv6_addr_t all_RPL_nodes = GNRC_RPL_ALL_NODES_ADDR;
                if_id = gnrc_ipv6_netif_find_by_addr(NULL, &all_RPL_nodes);
                /* check for the auto address-configuration flag */
                if ((gnrc_netapi_get(if_id, NETOPT_IPV6_IID, 0, &iid, sizeof(eui64_t)) < 0) &&
                        !(pi->LAR_flags & GNRC_RPL_PREFIX_AUTO_ADDRESS_BIT)) {
                    break;
                }
                ipv6_addr_set_aiid(&pi->prefix, iid.uint8);
                gnrc_ipv6_netif_add_addr(if_id, &pi->prefix, pi->prefix_len, 0);

                break;

            case (GNRC_RPL_OPT_TARGET):
                DEBUG("RPL: RPL TARGET DAO option parsed\n");
                *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_TARGET;
                if_id = gnrc_ipv6_netif_find_by_prefix(NULL, &(inst->dodag.dodag_id));
                if (if_id == KERNEL_PID_UNDEF) {
                    DEBUG("RPL: no interface found for the configured DODAG id\n");
                    return false;
                }

                gnrc_rpl_opt_target_t *target = (gnrc_rpl_opt_target_t *) opt;
                if (first_target == NULL) {
                    first_target = target;
                }

                fib_add_entry(&gnrc_ipv6_fib_table, if_id, target->target.u8,
                              sizeof(ipv6_addr_t), AF_INET6, src->u8,
                              sizeof(ipv6_addr_t), AF_INET6,
                              (inst->dodag.default_lifetime * inst->dodag.lifetime_unit) *
                              SEC_IN_MS);
                break;

            case (GNRC_RPL_OPT_TRANSIT):
                DEBUG("RPL: RPL TRANSIT INFO DAO option parsed\n");
                *included_opts |= ((uint32_t) 1) << GNRC_RPL_OPT_TRANSIT;
                gnrc_rpl_opt_transit_t *transit = (gnrc_rpl_opt_transit_t *) opt;
                if (first_target == NULL) {
                    DEBUG("RPL: Encountered a RPL TRANSIT DAO option without \
a preceding RPL TARGET DAO option\n");
                    break;
                }

                do {
                    fib_update_entry(&gnrc_ipv6_fib_table,
                                     first_target->target.u8,
                                     sizeof(ipv6_addr_t), src->u8,
                                     sizeof(ipv6_addr_t), AF_INET6,
                                     (transit->path_lifetime *
                                      inst->dodag.lifetime_unit * SEC_IN_MS));
                    first_target = (gnrc_rpl_opt_target_t *) (((uint8_t *) (first_target)) +
                        sizeof(gnrc_rpl_opt_t) + first_target->length);
                }
                while (first_target->type == GNRC_RPL_OPT_TARGET);

                first_target = NULL;
                break;

        }
        l += opt->length + sizeof(gnrc_rpl_opt_t);
        opt = (gnrc_rpl_opt_t *) (((uint8_t *) (opt + 1)) + opt->length);
    }
    return true;
}

static bool _gnrc_rpl_check_DIO_validity(gnrc_rpl_dio_t *dio, uint16_t len)
{
    uint16_t expected_len = sizeof(*dio) + sizeof(icmpv6_hdr_t);

    if (expected_len <= len) {
        return true;
    }

    DEBUG("RPL: wrong DIO len: %d, expected: %d\n", len, expected_len);

    return false;
}

void gnrc_rpl_recv_DIO(gnrc_rpl_dio_t *dio, ipv6_addr_t *src, uint16_t len)
{
    gnrc_rpl_instance_t *inst = NULL;

    if (!_gnrc_rpl_check_DIO_validity(dio, len)) {
        return;
    }

    len -= (sizeof(gnrc_rpl_dio_t) + sizeof(icmpv6_hdr_t));

    if (gnrc_rpl_instance_add(dio->instance_id, &inst)) {
        /* new instance and DODAG */

        if (byteorder_ntohs(dio->rank) == GNRC_RPL_INFINITE_RANK) {
            DEBUG("RPL: ignore INFINITE_RANK DIO when we are not yet part of this DODAG\n");
            gnrc_rpl_instance_remove(inst);
            return;
        }

        inst->mop = (dio->g_mop_prf >> GNRC_RPL_MOP_SHIFT) & GNRC_RPL_SHIFTED_MOP_MASK;
        inst->of = gnrc_rpl_get_of_for_ocp(GNRC_RPL_DEFAULT_OCP);
        gnrc_rpl_dodag_init(inst, &dio->dodag_id);

        gnrc_rpl_parent_t *parent = NULL;

        if (!gnrc_rpl_parent_add_by_addr(inst, src, &parent) && (parent == NULL)) {
            DEBUG("RPL: Could not allocate new parent.\n");
            gnrc_rpl_instance_remove(inst);
            return;
        }

        inst->dodag.version = dio->version_number;
        inst->dodag.grounded = dio->g_mop_prf >> GNRC_RPL_GROUNDED_SHIFT;
        inst->dodag.prf = dio->g_mop_prf & GNRC_RPL_PRF_MASK;

        parent->rank = byteorder_ntohs(dio->rank);

        uint32_t included_opts = 0;
        if(!_parse_options(GNRC_RPL_ICMPV6_CODE_DIO, inst, (gnrc_rpl_opt_t *)(dio + 1), len, NULL,
                           &included_opts)) {
            DEBUG("RPL: Error encountered during DIO option parsing - remove DODAG\n");
            gnrc_rpl_instance_remove(inst);
            return;
        }

        if (!(included_opts & (((uint32_t) 1) << GNRC_RPL_OPT_DODAG_CONF))) {
            DEBUG("RPL: DIO without DODAG_CONF option - remove DODAG and request new DIO\n");
            gnrc_rpl_instance_remove(inst);
            gnrc_rpl_send_DIS(NULL, src);
            return;
        }

        gnrc_rpl_delay_dao(inst);
        trickle_start(gnrc_rpl_pid, &(inst->dodag.trickle), GNRC_RPL_MSG_TYPE_TRICKLE_INTERVAL,
                      GNRC_RPL_MSG_TYPE_TRICKLE_CALLBACK, (1 << inst->dodag.dio_min),
                      inst->dodag.dio_interval_doubl, inst->dodag.dio_redun);

        gnrc_rpl_parent_update(inst, parent);
        DEBUG("RPL: Joined DODAG (%s).\n",
                ipv6_addr_to_str(addr_str, &dio->dodag_id, sizeof(addr_str)));
        return;
    }
    else if (inst == NULL) {
        DEBUG("RPL: Could not allocate a new instance.\n");
        return;
    }
    else {
        /* instance exists already */
        /* ignore dodags with other dodag_id's for now */
        /* TODO: choose DODAG with better rank */
        if (memcmp(&(inst->dodag.dodag_id), &dio->dodag_id, sizeof(ipv6_addr_t)) != 0) {
            DEBUG("RPL: DIO received from another DODAG, but same instance - ignore\n");
            return;
        }
    }

    if (inst->mop != ((dio->g_mop_prf >> GNRC_RPL_MOP_SHIFT) & GNRC_RPL_SHIFTED_MOP_MASK)) {
        DEBUG("RPL: invalid MOP for this instance.\n");
        return;
    }

    if (GNRC_RPL_COUNTER_GREATER_THAN(dio->version_number, inst->dodag.version)) {
        if (inst->dodag.node_status == GNRC_RPL_ROOT_NODE) {
            inst->dodag.version = GNRC_RPL_COUNTER_INCREMENT(dio->version_number);
            trickle_reset_timer(&(inst->dodag.trickle));
        }
        else {
            inst->dodag.version = dio->version_number;
            gnrc_rpl_local_repair(inst);
        }
    }
    else if (GNRC_RPL_COUNTER_GREATER_THAN(inst->dodag.version, dio->version_number)) {
        trickle_reset_timer(&(inst->dodag.trickle));
        return;
    }

    if (inst->dodag.node_status == GNRC_RPL_ROOT_NODE) {
        if (byteorder_ntohs(dio->rank) != GNRC_RPL_INFINITE_RANK) {
            trickle_increment_counter(&(inst->dodag.trickle));
        }
        else {
            trickle_reset_timer(&(inst->dodag.trickle));
        }
        return;
    }

    gnrc_rpl_parent_t *parent = NULL;

    if (!gnrc_rpl_parent_add_by_addr(inst, src, &parent) && (parent == NULL)) {
        DEBUG("RPL: Could not allocate new parent.\n");
        return;
    }
    /* cppcheck-suppress nullPointer */
    else if (parent != NULL) {
        trickle_increment_counter(&(inst->dodag.trickle));
    }

    /* gnrc_rpl_parent_add_by_addr should have set this already */
    assert(parent != NULL);

    parent->rank = byteorder_ntohs(dio->rank);

    gnrc_rpl_parent_update(inst, parent);

    /* sender of incoming DIO is not a parent of mine (anymore) and has an INFINITE rank
       and I have a rank != INFINITE_RANK */
    if (parent->state == 0) {
        if ((byteorder_ntohs(dio->rank) == GNRC_RPL_INFINITE_RANK)
             && (inst->dodag.my_rank != GNRC_RPL_INFINITE_RANK)) {
            trickle_reset_timer(&(inst->dodag.trickle));
            return;
        }
    }
    /* incoming DIO is from pref. parent */
    else if (parent == inst->parents) {
        if (parent->dtsn != dio->dtsn) {
            gnrc_rpl_delay_dao(inst);
        }
        parent->dtsn = dio->dtsn;
        inst->dodag.grounded = dio->g_mop_prf >> GNRC_RPL_GROUNDED_SHIFT;
        inst->dodag.prf = dio->g_mop_prf & GNRC_RPL_PRF_MASK;
        uint32_t included_opts = 0;
        if(!_parse_options(GNRC_RPL_ICMPV6_CODE_DIO, inst, (gnrc_rpl_opt_t *)(dio + 1), len, NULL,
                           &included_opts)) {
            DEBUG("RPL: Error encountered during DIO option parsing - remove DODAG\n");
            gnrc_rpl_instance_remove(inst);
            return;
        }
    }
}

void _dao_fill_target(gnrc_rpl_opt_target_t *target, ipv6_addr_t *addr)
{
    target->type = GNRC_RPL_OPT_TARGET;
    target->length = sizeof(target->flags) + sizeof(target->prefix_length) + sizeof(target->target);
    target->flags = 0;
    target->prefix_length = 128;
    target->target = *addr;
}

void gnrc_rpl_send_DAO(gnrc_rpl_instance_t *inst, ipv6_addr_t *destination, uint8_t lifetime)
{
    size_t dst_size = GNRC_RPL_PARENTS_NUMOF;
    fib_destination_set_entry_t fib_dest_set[GNRC_RPL_PARENTS_NUMOF];

    if (inst== NULL) {
        DEBUG("RPL: Error - trying to send DAO without being part of a dodag.\n");
        return;
    }

    if (inst->dodag.node_status == GNRC_RPL_ROOT_NODE) {
        return;
    }

    if (destination == NULL) {
        if (inst->parents == NULL) {
            DEBUG("RPL: dodag has no preferred parent\n");
            return;
        }

        destination = &(inst->parents->addr);
    }

    gnrc_pktsnip_t *pkt;
    icmpv6_hdr_t *icmp;
    gnrc_rpl_dao_t *dao;
    gnrc_rpl_opt_target_t *target;
    gnrc_rpl_opt_transit_t *transit;

    /* find my address */
    ipv6_addr_t *me = NULL;
    gnrc_ipv6_netif_find_by_prefix(&me, &(inst->dodag.dodag_id));
    if (me == NULL) {
        DEBUG("RPL: no address configured\n");
        return;
    }

    gnrc_ipv6_netif_addr_t *me_netif = gnrc_ipv6_netif_addr_get(me);
    if (me_netif == NULL) {
        DEBUG("RPL: no netif address found for %s\n", ipv6_addr_to_str(addr_str, me,
                    sizeof(addr_str)));
        return;
    }

    /* find prefix for my address */
    ipv6_addr_t prefix;
    ipv6_addr_init_prefix(&prefix, me, me_netif->prefix_len);
    fib_get_destination_set(&gnrc_ipv6_fib_table, prefix.u8,
                            sizeof(ipv6_addr_t), fib_dest_set, &dst_size);

    int size = sizeof(icmpv6_hdr_t) + sizeof(gnrc_rpl_dao_t) +
        (sizeof(gnrc_rpl_opt_target_t) * (dst_size + 1)) + sizeof(gnrc_rpl_opt_transit_t);

    bool local_instance = (inst->id & GNRC_RPL_INSTANCE_ID_MSB) ? true : false;

    if (local_instance) {
        size += sizeof(ipv6_addr_t);
    }

    if ((pkt = gnrc_icmpv6_build(NULL, ICMPV6_RPL_CTRL, GNRC_RPL_ICMPV6_CODE_DAO, size)) == NULL) {
        DEBUG("RPL: Send DAO - no space left in packet buffer\n");
        return;
    }

    icmp = (icmpv6_hdr_t *)pkt->data;
    dao = (gnrc_rpl_dao_t *)(icmp + 1);
    target = (gnrc_rpl_opt_target_t *) (dao + 1);

    dao->instance_id = inst->id;
    if (local_instance) {
        /* set the D flag to indicate that a DODAG id is present */
        dao->k_d_flags = GNRC_RPL_DAO_D_BIT;
        memcpy((dao + 1), &(inst->dodag.dodag_id), sizeof(ipv6_addr_t));
        target = (gnrc_rpl_opt_target_t *)(((uint8_t *) target) + sizeof(ipv6_addr_t));
    }
    else {
        dao->k_d_flags = 0;
    }

    /* set the K flag to indicate that ACKs are required */
    dao->k_d_flags |= GNRC_RPL_DAO_K_BIT;
    dao->dao_sequence = inst->dodag.dao_seq;
    dao->reserved = 0;

    /* add own address */
    _dao_fill_target(target, me);

    /* add children */
    for (size_t i = 0; i < dst_size; ++i) {
        target = (target + 1);
        _dao_fill_target(target, ((ipv6_addr_t *) fib_dest_set[i].dest));
    }

    transit = (gnrc_rpl_opt_transit_t *) (target + 1);
    transit->type = GNRC_RPL_OPT_TRANSIT;
    transit->length = sizeof(transit->e_flags) + sizeof(transit->path_control) +
        sizeof(transit->path_sequence) + sizeof(transit->path_lifetime);
    transit->e_flags = 0;
    transit->path_control = 0;
    transit->path_sequence = 0;
    transit->path_lifetime = lifetime;

    gnrc_rpl_send(pkt, NULL, destination, &(inst->dodag.dodag_id));

    GNRC_RPL_COUNTER_INCREMENT(inst->dodag.dao_seq);
}

void gnrc_rpl_send_DAO_ACK(gnrc_rpl_instance_t *inst, ipv6_addr_t *destination, uint8_t seq)
{
    if (inst == NULL) {
        DEBUG("RPL: Error - trying to send DAO-ACK without being part of a dodag.\n");
        return;
    }

    gnrc_pktsnip_t *pkt;
    icmpv6_hdr_t *icmp;
    gnrc_rpl_dao_ack_t *dao_ack;
    int size = sizeof(icmpv6_hdr_t) + sizeof(gnrc_rpl_dao_ack_t);
    bool local_instance = (inst->id & GNRC_RPL_INSTANCE_ID_MSB) ? true : false;

    if (local_instance) {
        size += sizeof(ipv6_addr_t);
    }

    if ((pkt = gnrc_icmpv6_build(NULL, ICMPV6_RPL_CTRL, GNRC_RPL_ICMPV6_CODE_DAO_ACK, size)) == NULL) {
        DEBUG("RPL: Send DAOACK - no space left in packet buffer\n");
        return;
    }

    icmp = (icmpv6_hdr_t *)pkt->data;
    dao_ack = (gnrc_rpl_dao_ack_t *)(icmp + 1);

    dao_ack->instance_id = inst->id;
    if (local_instance) {
        /* set the D flag to indicate that a DODAG id is present */
        dao_ack->d_reserved = GNRC_RPL_DAO_ACK_D_BIT;
        memcpy((dao_ack + 1), &(inst->dodag.dodag_id), sizeof(ipv6_addr_t));
    }
    else {
        dao_ack->d_reserved = 0;
    }

    dao_ack->dao_sequence = seq;
    dao_ack->status = 0;

    gnrc_rpl_send(pkt, NULL, destination, &(inst->dodag.dodag_id));
}

static bool _gnrc_rpl_check_DAO_validity(gnrc_rpl_dao_t *dao, uint16_t len)
{
    uint16_t expected_len = sizeof(*dao) + sizeof(icmpv6_hdr_t);

    if ((dao->k_d_flags & GNRC_RPL_DAO_D_BIT)) {
        expected_len += sizeof(ipv6_addr_t);
    }

    if (expected_len <= len) {
        return true;
    }

    DEBUG("RPL: wrong DAO len: %d, expected: %d\n", len, expected_len);

    return false;
}

void gnrc_rpl_recv_DAO(gnrc_rpl_dao_t *dao, ipv6_addr_t *src, uint16_t len)
{
    gnrc_rpl_instance_t *inst = NULL;

    if (!_gnrc_rpl_check_DAO_validity(dao, len)) {
        return;
    }

    gnrc_rpl_opt_t *opts = (gnrc_rpl_opt_t *) (dao + 1);

    if ((inst = gnrc_rpl_instance_get(dao->instance_id)) == NULL) {
        DEBUG("RPL: DAO with unknown instance id (%d) received\n", dao->instance_id);
        return;
    }

    len -= (sizeof(gnrc_rpl_dao_t) + sizeof(icmpv6_hdr_t));

    /* check if the D flag is set before accessing the DODAG id */
    if ((dao->k_d_flags & GNRC_RPL_DAO_D_BIT)) {
        if (memcmp(&(inst->dodag.dodag_id), (ipv6_addr_t *)(dao + 1), sizeof(ipv6_addr_t)) != 0) {
            DEBUG("RPL: DAO with unknown DODAG id (%s)\n", ipv6_addr_to_str(addr_str,
                        (ipv6_addr_t *)(dao + 1), sizeof(addr_str)));
            return;
        }
        opts = (gnrc_rpl_opt_t *)(((uint8_t *) opts) + sizeof(ipv6_addr_t));
        len -= sizeof(ipv6_addr_t);
    }

    uint32_t included_opts = 0;
    if(!_parse_options(GNRC_RPL_ICMPV6_CODE_DAO, inst, opts, len, src, &included_opts)) {
        DEBUG("RPL: Error encountered during DAO option parsing - ignore DAO\n");
        return;
    }

    /* send a DAO-ACK if K flag is set */
    if (dao->k_d_flags & GNRC_RPL_DAO_K_BIT) {
        gnrc_rpl_send_DAO_ACK(inst, src, dao->dao_sequence);
    }

    gnrc_rpl_delay_dao(inst);
}

static bool _gnrc_rpl_check_DAO_ACK_validity(gnrc_rpl_dao_ack_t *dao_ack, uint16_t len)
{
    uint16_t expected_len = sizeof(*dao_ack) + sizeof(icmpv6_hdr_t);

    if ((dao_ack->d_reserved & GNRC_RPL_DAO_ACK_D_BIT)) {
        expected_len += sizeof(ipv6_addr_t);
    }

    if (expected_len == len) {
        return true;
    }

    DEBUG("RPL: wrong DAO-ACK len: %d, expected: %d\n", len, expected_len);

    return false;
}

void gnrc_rpl_recv_DAO_ACK(gnrc_rpl_dao_ack_t *dao_ack, uint16_t len)
{
    gnrc_rpl_instance_t *inst = NULL;

    if (!_gnrc_rpl_check_DAO_ACK_validity(dao_ack, len)) {
        return;
    }

    if ((inst = gnrc_rpl_instance_get(dao_ack->instance_id)) == NULL) {
        DEBUG("RPL: DAO-ACK with unknown instance id (%d) received\n", dao_ack->instance_id);
        return;
    }

    /* check if the D flag is set before accessing the DODAG id */
    if ((dao_ack->d_reserved & GNRC_RPL_DAO_ACK_D_BIT)) {
        if (memcmp(&(inst->dodag.dodag_id), (ipv6_addr_t *)(dao_ack + 1), sizeof(ipv6_addr_t))
            != 0) {
            DEBUG("RPL: DAO-ACK with unknown DODAG id (%s)\n", ipv6_addr_to_str(addr_str,
                        (ipv6_addr_t *)(dao_ack + 1), sizeof(addr_str)));
            return;
        }
    }

    if ((dao_ack->status != 0) && (dao_ack->dao_sequence != inst->dodag.dao_seq)) {
        DEBUG("RPL: DAO-ACK sequence (%d) does not match expected sequence (%d)\n",
                dao_ack->dao_sequence, inst->dodag.dao_seq);
        return;
    }

    inst->dodag.dao_ack_received = true;
    gnrc_rpl_long_delay_dao(inst);
}

/**
 * @}
 */
