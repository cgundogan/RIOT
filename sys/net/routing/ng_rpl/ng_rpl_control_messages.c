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
 */
#include "net/ng_rpl.h"
#include "inet_ntop.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG
static char addr_str[NG_IPV6_ADDR_MAX_STR_LEN];
#endif

#define NG_RPL_OPT_LEN                  2
#define NG_RPL_GROUNDED_SHIFT           7
#define NG_RPL_MOP_SHIFT                3
#define NG_RPL_OPT_DODAG_CONF_LEN       14
#define NG_RPL_SHIFTED_MOP_MASK         0x7
#define NG_RPL_PRF_MASK                 0x7

void _ng_rpl_send(ng_pktsnip_t *pkt, ng_ipv6_addr_t *src, ng_ipv6_addr_t *dst)
{
    ng_pktsnip_t *hdr;
    ng_netreg_entry_t *sendto = NULL;
    ng_ipv6_addr_t all_RPL_nodes = NG_IPV6_ADDR_ALL_RPL_NODES;
    kernel_pid_t iface = ng_ipv6_netif_find_by_addr(NULL, &all_RPL_nodes);
    if (iface == KERNEL_PID_UNDEF) {
        DEBUG("RPL: no suitable interface found for this destination address\n");
        ng_pktbuf_release(pkt);
        return;
    }

    if (src == NULL) {
        ng_ipv6_addr_t ll_addr;
        ng_ipv6_addr_set_link_local_prefix(&ll_addr);
        src = ng_ipv6_netif_match_prefix(iface, &ll_addr);
        if (src == NULL) {
            DEBUG("RPL: no suitable src address found for this destination address\n");
            ng_pktbuf_release(pkt);
            return;
        }
    }

    if (dst == NULL) {
        dst = &all_RPL_nodes;
    }

    hdr = ng_ipv6_hdr_build(pkt, (uint8_t *)src, src ? sizeof(ng_ipv6_addr_t) : 0,
            (uint8_t *)dst, sizeof(ng_ipv6_addr_t));

    if (hdr == NULL) {
        DEBUG("RPL: no space left in packet buffer\n");
        ng_pktbuf_release(pkt);
        return;
    }

    pkt = hdr;

    sendto = ng_netreg_lookup(NG_NETTYPE_IPV6, NG_NETREG_DEMUX_CTX_ALL);

    if (sendto == NULL) {
        DEBUG("RPL: no receivers for IPv6 packets\n");
        ng_pktbuf_release(pkt);
        return;
    }

    ng_netapi_send(sendto->pid, pkt);
}

void ng_rpl_send_DIO(ng_rpl_dodag_t *dodag, ng_ipv6_addr_t *destination)
{
    if (dodag == NULL) {
        DEBUG("RPL: Error - trying to send DIO without being part of a dodag.\n");
        return;
    }

#ifdef MODULE_NG_RPL_P2P
    if (dodag->p2p_ext && (dodag->p2p_ext->for_me || (dodag->p2p_ext->lifetime_sec < 0))) {
        trickle_stop(&dodag->trickle);
        return;
    }
#endif

    ng_pktsnip_t *pkt;
    ng_icmpv6_hdr_t *icmp;
    ng_rpl_dio_t *dio;
    ng_rpl_opt_dodag_conf_t *dodag_conf;
    uint8_t *pos;
    int size = sizeof(ng_icmpv6_hdr_t) + sizeof(ng_rpl_dio_t);

    if ((dodag->dodag_conf_counter % 3) == 0) {
        size += sizeof(ng_rpl_opt_dodag_conf_t);
    }

#ifdef MODULE_NG_RPL_P2P
    uint8_t p2p_addresses_len = 0;
    if (dodag->p2p_ext && !dodag->p2p_ext->for_me) {
        p2p_addresses_len = dodag->p2p_ext->no_of_addresses *
            (sizeof(ng_ipv6_addr_t) - dodag->p2p_ext->compr);
        size += sizeof(ng_rpl_p2p_opt_rdo_t) + p2p_addresses_len;
    }
#endif

    if ((pkt = ng_icmpv6_build(NULL, NG_ICMPV6_RPL_CTRL, NG_RPL_ICMPV6_CODE_DIO, size)) == NULL) {
        DEBUG("RPL: no space left in packet buffer\n");
        return;
    }

    icmp = (ng_icmpv6_hdr_t *)pkt->data;
    dio = (ng_rpl_dio_t *)(icmp + 1);
    pos = (uint8_t *) dio;
    dio->instance_id = dodag->instance->id;
    dio->version_number = dodag->version;
    dio->rank = byteorder_htons(dodag->my_rank);
    dio->g_mop_prf = (dodag->grounded << NG_RPL_GROUNDED_SHIFT) |
        (dodag->instance->mop << NG_RPL_MOP_SHIFT) | dodag->prf;
    dio->dtsn = dodag->dtsn;
    dio->flags = 0;
    dio->reserved = 0;
    dio->dodag_id = dodag->dodag_id;

    pos += sizeof(*dio);

    if ((dodag->dodag_conf_counter % 3) == 0) {
        dodag_conf = (ng_rpl_opt_dodag_conf_t *) pos;
        dodag_conf->type = NG_RPL_OPT_DODAG_CONF;
        dodag_conf->length = NG_RPL_OPT_DODAG_CONF_LEN;
        dodag_conf->flags_a_pcs = 0;
        dodag_conf->dio_int_doubl = dodag->dio_interval_doubl;
        dodag_conf->dio_int_min = dodag->dio_min;
        dodag_conf->dio_redun = dodag->dio_redun;
        dodag_conf->max_rank_inc = byteorder_htons(dodag->instance->max_rank_inc);
        dodag_conf->min_hop_rank_inc = byteorder_htons(dodag->instance->min_hop_rank_inc);
        dodag_conf->ocp = byteorder_htons(dodag->instance->of->ocp);
        dodag_conf->reserved = 0;
        dodag_conf->default_lifetime = dodag->default_lifetime;
        dodag_conf->lifetime_unit = byteorder_htons(dodag->lifetime_unit);
        pos += sizeof(*dodag_conf);
    }

    dodag->dodag_conf_counter++;

#ifdef MODULE_NG_RPL_P2P
    ng_rpl_p2p_opt_rdo_t *rdo;
    if (dodag->p2p_ext && !dodag->p2p_ext->for_me) {
        rdo = (ng_rpl_p2p_opt_rdo_t *) pos;
        rdo->type = NG_RPL_OPT_P2P_RDO;
        rdo->length = sizeof(*rdo) - NG_RPL_OPT_LEN + p2p_addresses_len;
        rdo->compr_flags = (dodag->p2p_ext->reply << 7) | (dodag->p2p_ext->hop_by_hop << 6) |
            ((dodag->p2p_ext->no_of_routes & 0x3) << 4) | (dodag->p2p_ext->compr & 0xF);
        rdo->lifetime_maxrank_nexthop = ((dodag->p2p_ext->lifetime & 0x3) << 6) |
            (dodag->p2p_ext->maxrank & 0x3F);
        rdo->target = dodag->p2p_ext->target;

        uint8_t *addr = (uint8_t *) (rdo + 1);
        for (uint8_t i = 0, addr_len = (sizeof(ng_ipv6_addr_t) - dodag->p2p_ext->compr);
                i < dodag->p2p_ext->no_of_addresses; i++, addr += addr_len) {
            memcpy(addr, &dodag->p2p_ext->addresses[i], addr_len);
        }
        pos += sizeof(ng_rpl_p2p_opt_rdo_t) + p2p_addresses_len;
    }
#endif

    _ng_rpl_send(pkt, NULL, destination);
}

void ng_rpl_send_DIS(ng_rpl_dodag_t *dodag, ng_ipv6_addr_t *destination)
{
    (void) dodag;
#ifdef MODULE_NG_RPL_P2P
    if (dodag && dodag->p2p_ext) {
        DEBUG("RPL: Not sending DIS for P2P RPL DODAG\n");
        return;
    }
#endif
    ng_pktsnip_t *pkt;
    ng_icmpv6_hdr_t *icmp;
    ng_rpl_dis_t *dis;
    int size = sizeof(ng_icmpv6_hdr_t) + sizeof(ng_rpl_dis_t) + 4;

    if ((pkt = ng_icmpv6_build(NULL, NG_ICMPV6_RPL_CTRL, NG_RPL_ICMPV6_CODE_DIS, size)) == NULL) {
        DEBUG("RPL: no space left in packet buffer\n");
        return;
    }

    icmp = (ng_icmpv6_hdr_t *)pkt->data;
    dis = (ng_rpl_dis_t *)(icmp + 1);
    dis->flags = 0;;
    dis->reserved = 0;;
    memset((dis + 1), 0, 4);

    _ng_rpl_send(pkt, NULL, destination);
}

void ng_rpl_recv_DIS(ng_rpl_dis_t *dis, ng_ipv6_addr_t *src, ng_ipv6_addr_t *dst, uint16_t len)
{
    /* TODO handle Solicited Information Option */
    (void) dis;
    (void) len;

    if (ng_ipv6_addr_is_multicast(dst)) {
        for (uint8_t i = 0; i < NG_RPL_DODAGS_NUMOF; ++i) {
            if (ng_rpl_dodags[i].state != 0) {
                trickle_reset_timer(&ng_rpl_dodags[i].trickle);
            }
        }
    }
    else {
        for (uint8_t i = 0; i < NG_RPL_DODAGS_NUMOF; ++i) {
            if (ng_rpl_dodags[i].state != 0) {
#ifdef MODULE_NG_RPL_P2P
                if (ng_rpl_dodags[i].p2p_ext) {
                    DEBUG("RPL: Not responding to DIS for P2P RPL DODAG\n");
                    continue;
                }
#endif
                ng_rpl_dodags[i].dodag_conf_counter = 0;
                ng_rpl_send_DIO(&ng_rpl_dodags[i], src);
            }
        }
    }

    return;
}

void _parse_options(ng_rpl_dodag_t *dodag, ng_rpl_opt_t *opt, uint16_t len, ng_ipv6_addr_t *src)
{
    uint16_t l = 0;
    ng_rpl_opt_target_t *first_target = NULL;
    while(l < len) {
        switch(opt->type) {
            case (NG_RPL_OPT_PAD1): {
                DEBUG("RPL: PAD1 option parsed\n");
                l += 1;
                opt = (ng_rpl_opt_t *) (((uint8_t *) opt) + 1);
                continue;
            }
            case (NG_RPL_OPT_PADN): {
                DEBUG("RPL: PADN option parsed\n");
                break;
            }
            case (NG_RPL_OPT_DODAG_CONF): {
                DEBUG("RPL: DODAG CONF DIO option parsed\n");
                ng_rpl_opt_dodag_conf_t *dc = (ng_rpl_opt_dodag_conf_t *) opt;
                dodag->dio_interval_doubl = dc->dio_int_doubl;
                dodag->dio_min = dc->dio_int_min;
                dodag->dio_redun = dc->dio_redun;
                dodag->instance->max_rank_inc = byteorder_ntohs(dc->max_rank_inc);
                dodag->instance->min_hop_rank_inc = byteorder_ntohs(dc->min_hop_rank_inc);
                dodag->default_lifetime = dc->default_lifetime;
                dodag->lifetime_unit = byteorder_ntohs(dc->lifetime_unit);
                dodag->instance->of =
                    (ng_rpl_of_t *) ng_rpl_get_of_for_ocp(byteorder_ntohs(dc->ocp));

                dodag->trickle.Imin = (1 << dodag->dio_min);
                dodag->trickle.Imax = dodag->dio_interval_doubl;
                dodag->trickle.k = dodag->dio_redun;
                break;
            }
            case (NG_RPL_OPT_TARGET): {
                DEBUG("RPL: RPL TARGET DAO option parsed\n");
                ng_rpl_opt_target_t *target = (ng_rpl_opt_target_t *) opt;
                if (first_target == NULL) {
                    first_target = target;
                }

                kernel_pid_t if_id = ng_ipv6_netif_find_by_prefix(NULL, &dodag->dodag_id);
                if (if_id == KERNEL_PID_UNDEF) {
                    DEBUG("RPL: no interface found for the configured DODAG id\n");
                    break;
                }

                fib_add_entry(if_id, target->target.u8, sizeof(ng_ipv6_addr_t), AF_INET6, src->u8,
                        sizeof(ng_ipv6_addr_t), AF_INET6,
                        (dodag->default_lifetime * dodag->lifetime_unit) * SEC_IN_MS);
                break;
            }
            case (NG_RPL_OPT_TRANSIT): {
                DEBUG("RPL: RPL TRANSIT INFO DAO option parsed\n");
                ng_rpl_opt_transit_t *transit = (ng_rpl_opt_transit_t *) opt;
                if (first_target == NULL) {
                    DEBUG("RPL: Encountered a RPL TRANSIT DAO option without \
a preceding RPL TARGET DAO option\n");
                    break;
                }

                do {
                    fib_update_entry(first_target->target.u8, sizeof(ng_ipv6_addr_t),
                            src->u8, sizeof(ng_ipv6_addr_t), AF_INET6,
                            (transit->path_lifetime * dodag->lifetime_unit * SEC_IN_MS));
                    first_target = (ng_rpl_opt_target_t *) (((uint8_t *) (first_target)) +
                        sizeof(ng_rpl_opt_t) + first_target->length);
                }
                while (first_target->type == NG_RPL_OPT_TARGET);

                first_target = NULL;
                break;
            }
#if MODULE_NG_RPL_P2P
            case (NG_RPL_OPT_P2P_RDO): {
                DEBUG("RPL: P2P RDO option parsed\n");
                ng_rpl_p2p_opt_rdo_t *rdo = (ng_rpl_p2p_opt_rdo_t *) opt;

                uint8_t addr_num = (rdo->length - sizeof(*rdo) + NG_RPL_OPT_LEN) /
                    (sizeof(ng_ipv6_addr_t) - dodag->p2p_ext->compr);

                dodag->p2p_ext->for_me = ng_ipv6_netif_find_by_addr(NULL, &rdo->target) ==
                    KERNEL_PID_UNDEF ? 0 : 1;

                if (addr_num >= NG_RPL_P2P_RDO_MAX_ADDRESSES) {
                    DEBUG("RPL: cannot parse RDO - too many hops\n");
                    break;
                }

                dodag->p2p_ext->reply = (rdo->compr_flags & (1 << 7)) >> 7;
                dodag->p2p_ext->hop_by_hop = (rdo->compr_flags & (1 << 6)) >> 6;
                dodag->p2p_ext->no_of_routes = (rdo->compr_flags & (0x3 << 4)) >> 4;
                dodag->p2p_ext->compr = rdo->compr_flags & 0xF;
                dodag->p2p_ext->lifetime = (rdo->lifetime_maxrank_nexthop & (0x3 << 6)) >> 6;
                dodag->p2p_ext->maxrank = rdo->lifetime_maxrank_nexthop & 0x3F;
                dodag->p2p_ext->target = rdo->target;

                memset(&dodag->p2p_ext->addresses, 0,
                        sizeof(ng_ipv6_addr_t) * NG_RPL_P2P_RDO_MAX_ADDRESSES);
                dodag->p2p_ext->no_of_addresses = 0;
                uint8_t *tmp = (uint8_t *) (rdo + 1);
                uint8_t *addr = NULL;
                uint8_t addr_len = sizeof(ng_ipv6_addr_t) - dodag->p2p_ext->compr;
                uint8_t i = 0;
                for (i = 0; i < addr_num; i++) {
                    addr = ((uint8_t *) &dodag->p2p_ext->addresses[i]) + dodag->p2p_ext->compr;
                    memcpy(addr, tmp, addr_len);
                    tmp += addr_len;
                    dodag->p2p_ext->no_of_addresses++;
                }

                if (!dodag->p2p_ext->for_me) {
                    ng_ipv6_addr_t *me = NULL;
                    ng_ipv6_netif_find_by_prefix(&me, &dodag->dodag_id);
                    if (me == NULL) {
                        DEBUG("RPL: no address configured\n");
                        break;
                    }
                    addr = ((uint8_t *) &dodag->p2p_ext->addresses[i]) + dodag->p2p_ext->compr;
                    memcpy(addr, ((uint8_t *) me) + dodag->p2p_ext->compr, addr_len);
                    dodag->p2p_ext->no_of_addresses++;
                }
                else {
                    ng_rpl_recv_send_DRO(dodag, NULL);
                }

                break;
            }
#endif
        }
        l += opt->length + sizeof(ng_rpl_opt_t);
        opt = (ng_rpl_opt_t *) (((uint8_t *) (opt + 1)) + opt->length);
    }
    return;
}

void ng_rpl_recv_DIO(ng_rpl_dio_t *dio, ng_ipv6_addr_t *src, uint16_t len)
{
    ng_rpl_instance_t *inst = NULL;
    ng_rpl_dodag_t *dodag = NULL;

    if (ng_rpl_instance_add(dio->instance_id, &inst)) {
        inst->mop = (dio->g_mop_prf >> NG_RPL_MOP_SHIFT) & NG_RPL_SHIFTED_MOP_MASK;
        inst->of = (ng_rpl_of_t *) ng_rpl_get_of_for_ocp(NG_RPL_DEFAULT_OCP);
    }
    else if (inst == NULL) {
        DEBUG("RPL: Could not allocate a new instance.\n");
        return;
    }

    if ((byteorder_ntohs(dio->rank) == NG_RPL_INFINITE_RANK) &&
            (ng_rpl_dodag_get(inst, &dio->dodag_id) == NULL)) {
        DEBUG("RPL: ignore INFINITE_RANK DIO when we are not part of this DODAG\n");
        ng_rpl_instance_remove(inst);
        return;
    }

    if (ng_rpl_dodag_add(inst, &dio->dodag_id, &dodag)) {
        DEBUG("RPL: Joined DODAG (%s).\n",
                ng_ipv6_addr_to_str(addr_str, &dio->dodag_id, sizeof(addr_str)));

        uint8_t tmp_len = len - (sizeof(ng_rpl_dio_t) + sizeof(ng_icmpv6_hdr_t));
        _parse_options(dodag, (ng_rpl_opt_t *)(dio + 1), tmp_len, NULL);

        ng_rpl_parent_t *parent = NULL;

        if (!ng_rpl_parent_add_by_addr(dodag, src, &parent) && (parent == NULL)) {
            DEBUG("RPL: Could not allocate new parent.\n");
            ng_rpl_dodag_remove(dodag);
            return;
        }

        trickle_start(ng_rpl_pid, &dodag->trickle, NG_RPL_MSG_TYPE_TRICKLE_INTERVAL,
                      NG_RPL_MSG_TYPE_TRICKLE_CALLBACK, (1 << dodag->dio_min),
                      dodag->dio_interval_doubl, dodag->dio_redun);
        dodag->version = dio->version_number;
        ng_rpl_delay_dao(dodag);
        parent->rank = byteorder_ntohs(dio->rank);
        ng_rpl_parent_update(dodag, parent);
#ifdef MODULE_NG_RPL_P2P
        if (dodag->p2p_ext) {
            dodag->p2p_ext->lifetime_sec = ng_rpl_p2p_lifetime_lookup[dodag->p2p_ext->lifetime];
        }
#endif
        return;
    }
    else if (dodag == NULL) {
        DEBUG("RPL: Could not allocate a new DODAG.\n");
        if (inst->dodags == NULL) {
            ng_rpl_instance_remove(inst);
        }
        return;
    }

#ifdef MODULE_NG_RPL_P2P
        if (dodag->p2p_ext && (dodag->p2p_ext->lifetime_sec < 0)) {
            return;
        }
#endif

    if (dodag->instance->mop !=
            ((dio->g_mop_prf >> NG_RPL_MOP_SHIFT) & NG_RPL_SHIFTED_MOP_MASK)) {
        DEBUG("RPL: invalid MOP for this instance.\n");
        return;
    }

    if (NG_RPL_COUNTER_GREATER_THAN(dio->version_number, dodag->version)) {
        if (dodag->node_status == NG_RPL_ROOT_NODE) {
            dodag->version = NG_RPL_COUNTER_INCREMENT(dio->version_number);
            trickle_reset_timer(&dodag->trickle);
        }
        else {
            dodag->version = dio->version_number;
            ng_rpl_local_repair(dodag);
        }
    }
    else if (NG_RPL_COUNTER_GREATER_THAN(dodag->version, dio->version_number)) {
        trickle_reset_timer(&dodag->trickle);
        return;
    }

    if (dodag->node_status == NG_RPL_ROOT_NODE) {
        if (byteorder_ntohs(dio->rank) != NG_RPL_INFINITE_RANK) {
            trickle_increment_counter(&dodag->trickle);
        }
        return;
    }

    dodag->grounded = dio->g_mop_prf >> NG_RPL_GROUNDED_SHIFT;
    dodag->prf = dio->g_mop_prf & NG_RPL_PRF_MASK;

    ng_rpl_parent_t *parent = NULL;

    if (!ng_rpl_parent_add_by_addr(dodag, src, &parent) && (parent == NULL)) {
        DEBUG("RPL: Could not allocate new parent.\n");
        if (dodag->parents == NULL) {
            ng_rpl_dodag_remove(dodag);
        }
        return;
    }
    else if (parent) {
        trickle_increment_counter(&dodag->trickle);
    }

    parent->rank = byteorder_ntohs(dio->rank);

    ng_rpl_parent_update(dodag, parent);

    if (parent->state != 0) {
        if (dodag->parents && (parent == dodag->parents) && (parent->dtsn != dio->dtsn)) {
            ng_rpl_delay_dao(dodag);
        }
        parent->dtsn = dio->dtsn;

        len -= (sizeof(ng_rpl_dio_t) + sizeof(ng_icmpv6_hdr_t));
        _parse_options(dodag, (ng_rpl_opt_t *)(dio + 1), len, NULL);
    }

    return;
}

void _dao_fill_target(ng_rpl_opt_target_t *target, ng_ipv6_addr_t *addr)
{
    target->type = NG_RPL_OPT_TARGET;
    target->length = sizeof(target->flags) + sizeof(target->prefix_length) + sizeof(target->target);
    target->flags = 0;
    target->prefix_length = 128;
    target->target = *addr;
    return;
}

void ng_rpl_send_DAO(ng_rpl_dodag_t *dodag, ng_ipv6_addr_t *destination, uint8_t lifetime)
{
    size_t dst_size = NG_RPL_PARENTS_NUMOF;
    fib_destination_set_entry_t fib_dest_set[NG_RPL_PARENTS_NUMOF];

    if (dodag == NULL) {
        DEBUG("RPL: Error - trying to send DIO without being part of a dodag.\n");
        return;
    }

    if (dodag->node_status == NG_RPL_ROOT_NODE) {
        return;
    }

    if (destination == NULL) {
        if (dodag->parents == NULL) {
            DEBUG("RPL: dodag has no preferred parent\n");
            return;
        }

        destination = &(dodag->parents->addr);
    }

    ng_pktsnip_t *pkt;
    ng_icmpv6_hdr_t *icmp;
    ng_rpl_dao_t *dao;
    ng_rpl_opt_target_t *target;
    ng_rpl_opt_transit_t *transit;

    /* find my address */
    ng_ipv6_addr_t *me = NULL;
    ng_ipv6_netif_find_by_prefix(&me, &dodag->dodag_id);
    if (me == NULL) {
        DEBUG("RPL: no address configured\n");
        return;
    }

    ng_ipv6_netif_addr_t *me_netif = ng_ipv6_netif_addr_get(me);
    if (me_netif == NULL) {
        DEBUG("RPL: no netif address found for %s\n", ng_ipv6_addr_to_str(addr_str, me,
                    sizeof(addr_str)));
        return;
    }

    /* find prefix for my address */
    ng_ipv6_addr_t prefix = *me;
    uint8_t pref_len = me_netif->prefix_len;

    uint8_t i = sizeof(prefix.u8) - 1;
    while (8 < pref_len) {
        prefix.u8[i] = 0;
        pref_len -= 8;
        i--;
    }
    if (pref_len != 0) {
        prefix.u8[i] = (prefix.u8[i] & (0xFF << (8 - pref_len)));
    }

    fib_get_destination_set(prefix.u8, sizeof(ng_ipv6_addr_t), fib_dest_set, &dst_size);

    int size = sizeof(ng_icmpv6_hdr_t) + sizeof(ng_rpl_dao_t) +
        (sizeof(ng_rpl_opt_target_t) * (dst_size + 1)) + sizeof(ng_rpl_opt_transit_t);

    if ((pkt = ng_icmpv6_build(NULL, NG_ICMPV6_RPL_CTRL, NG_RPL_ICMPV6_CODE_DAO, size)) == NULL) {
        DEBUG("RPL: no space left in packet buffer\n");
        return;
    }

    icmp = (ng_icmpv6_hdr_t *)pkt->data;
    dao = (ng_rpl_dao_t *)(icmp + 1);

    dao->instance_id = dodag->instance->id;
    /* set the D flag to indicate that a DODAG id is present */
    /* set the K flag to indicate that a ACKs are required */
    dao->k_d_flags = ((1 << 6) | (1 << 7));
    dao->dao_sequence = dodag->dao_seq;
    dao->dodag_id = dodag->dodag_id;
    dao->reserved = 0;

    /* add own address */
    target = (ng_rpl_opt_target_t *) (dao + 1);
    _dao_fill_target(target, me);
    /* add children */
    for (size_t i = 0; i < dst_size; ++i) {
        target = (target + 1);
        _dao_fill_target(target, ((ng_ipv6_addr_t *) fib_dest_set[i].dest));
    }

    transit = (ng_rpl_opt_transit_t *) (target + 1);
    transit->type = NG_RPL_OPT_TRANSIT;
    transit->length = sizeof(transit->e_flags) + sizeof(transit->path_control) +
        sizeof(transit->path_sequence) + sizeof(transit->path_lifetime);
    transit->e_flags = 0;
    transit->path_control = 0;
    transit->path_sequence = 0;
    transit->path_lifetime = lifetime;

    _ng_rpl_send(pkt, NULL, destination);

    NG_RPL_COUNTER_INCREMENT(dodag->dao_seq);

    return;
}

void ng_rpl_send_DAO_ACK(ng_rpl_dodag_t *dodag, ng_ipv6_addr_t *destination, uint8_t seq)
{
    if (dodag == NULL) {
        DEBUG("RPL: Error - trying to send DAO without being part of a dodag.\n");
        return;
    }

    ng_pktsnip_t *pkt;
    ng_icmpv6_hdr_t *icmp;
    ng_rpl_dao_ack_t *dao_ack;
    int size = sizeof(ng_icmpv6_hdr_t) + sizeof(ng_rpl_dao_ack_t);

    if ((pkt = ng_icmpv6_build(NULL, NG_ICMPV6_RPL_CTRL, NG_RPL_ICMPV6_CODE_DAO_ACK, size)) == NULL) {
        DEBUG("RPL: no space left in packet buffer\n");
        return;
    }

    icmp = (ng_icmpv6_hdr_t *)pkt->data;
    dao_ack = (ng_rpl_dao_ack_t *)(icmp + 1);

    dao_ack->instance_id = dodag->instance->id;
    dao_ack->d_reserved = (1 << 7);
    dao_ack->dao_sequence = seq;
    dao_ack->status = 0;
    dao_ack->dodag_id = dodag->dodag_id;

    _ng_rpl_send(pkt, NULL, destination);
    return;
}

#ifdef MODULE_NG_RPL_P2P
void ng_rpl_recv_send_DRO(ng_rpl_dodag_t *dodag, ng_rpl_p2p_dro_t *dro)
{
    if ((dodag == NULL) && (dro != NULL)) {
        ng_rpl_instance_t *inst;
        if ((inst = ng_rpl_instance_get(dro->instance_id)) == NULL) {
            DEBUG("RPL: Error - Instance (%d) does not exist\n", dro->instance_id);
            return;
        }
        if ((dodag = ng_rpl_dodag_get(inst, &dro->dodag_id)) == NULL) {
            DEBUG("RPL: Error - DODAG (%s) does not exist\n",
                    ng_ipv6_addr_to_str(addr_str, &dro->dodag_id, sizeof(addr_str)));
            return;
        }
    }

    ng_pktsnip_t *pkt;
    ng_icmpv6_hdr_t *icmp;
    ng_rpl_p2p_opt_rdo_t *rdo = NULL;
    uint8_t addr_size = 0;
    uint8_t addr_len = sizeof(ng_ipv6_addr_t) - dodag->p2p_ext->compr;

    int size = sizeof(ng_icmpv6_hdr_t) + sizeof(ng_rpl_p2p_dro_t);
    if (dodag->p2p_ext->for_me) {
        addr_size = dodag->p2p_ext->no_of_addresses * addr_len;
        size += sizeof(ng_rpl_p2p_opt_rdo_t) + addr_size;
    }
    else if (dro) {
        rdo = (ng_rpl_p2p_opt_rdo_t *) (dro + 1);
        size += rdo->length + NG_RPL_OPT_LEN;
    }
    else {
        DEBUG("RPL: Error - no DRO found\n");
        return;
    }

    if ((pkt = ng_icmpv6_build(NULL, NG_ICMPV6_RPL_CTRL, NG_RPL_ICMPV6_CODE_DRO, size)) == NULL) {
        DEBUG("RPL: no space left in packet buffer\n");
        return;
    }

    icmp = (ng_icmpv6_hdr_t *) pkt->data;

    if (dodag->p2p_ext->for_me) {

        if (dro != NULL) {
            DEBUG("RPL: ignore received DROs, because the target should not process them\n");
            ng_pktbuf_release(pkt);
            return;
        }

        dro = (ng_rpl_p2p_dro_t *) (icmp + 1);
        dro->instance_id = dodag->instance->id;
        dro->version = 0;
        dro->flags_reserved = byteorder_htons((0x3 << 14) | ((dodag->p2p_ext->dro_seq & 0x3) << 12));
        dro->dodag_id = dodag->dodag_id;

        rdo = (ng_rpl_p2p_opt_rdo_t *) (dro + 1);
        rdo->type = NG_RPL_OPT_P2P_RDO;
        rdo->length = sizeof(*rdo) - NG_RPL_OPT_LEN + addr_size;
        rdo->compr_flags = (dodag->p2p_ext->hop_by_hop << 6) | (dodag->p2p_ext->compr & 0xF);
        rdo->lifetime_maxrank_nexthop = (((rdo->length - 2 - sizeof(ng_ipv6_addr_t))
                    / addr_len) & 0x3F);
        rdo->target = dodag->p2p_ext->target;

        uint8_t *addr = (uint8_t *) (rdo + 1);
        for (uint8_t i = 0; i < dodag->p2p_ext->no_of_addresses; i++, addr += addr_len) {
            memcpy(addr, &dodag->p2p_ext->addresses[i], addr_len);
        }

        _ng_rpl_send(pkt, NULL, NULL);
    }
    else {
        ng_rpl_p2p_dro_t *copy_dro = (ng_rpl_p2p_dro_t *) (icmp + 1);
        memcpy(copy_dro, dro, (size - sizeof(ng_icmpv6_hdr_t)));
        ng_rpl_p2p_opt_rdo_t *copy_rdo = (ng_rpl_p2p_opt_rdo_t *) (copy_dro + 1);

        ng_ipv6_addr_t addr;
        if (copy_rdo->lifetime_maxrank_nexthop > 0) {
            memcpy((((uint8_t *) &addr) + dodag->p2p_ext->compr),
                    ((uint8_t *) (copy_rdo + 1)) + addr_len * (--copy_rdo->lifetime_maxrank_nexthop),
                    addr_len);
        }

        ng_ipv6_addr_t *me = NULL, next_hop;
        kernel_pid_t if_id = KERNEL_PID_UNDEF;

        if(((rdo->lifetime_maxrank_nexthop > 0) &&
                    ((if_id = ng_ipv6_netif_find_by_addr(&me, &addr)) != KERNEL_PID_UNDEF)) ||
                (dodag->node_status == NG_RPL_ROOT_NODE)) {
            /* if true, the current node received this DRO directly from target => use target */
            if ((addr_len * (rdo->lifetime_maxrank_nexthop)) ==
                    (copy_rdo->length - 2 - sizeof(ng_ipv6_addr_t))) {
                next_hop = copy_rdo->target;
            }
            /* if false, the current node is somewhere on the path => use addresses[NH + 1] */
            else {
                memcpy((((uint8_t *) &next_hop) + dodag->p2p_ext->compr),
                        ((uint8_t *) (copy_rdo + 1)) + addr_len * (rdo->lifetime_maxrank_nexthop),
                        addr_len);
            }

            fib_add_entry(if_id, dodag->p2p_ext->target.u8, sizeof(ng_ipv6_addr_t), AF_INET6,
                    next_hop.u8, sizeof(ng_ipv6_addr_t), AF_INET6,
                    dodag->default_lifetime * dodag->lifetime_unit * SEC_IN_MS);

            if (dodag->node_status != NG_RPL_ROOT_NODE) {
                _ng_rpl_send(pkt, NULL, NULL);
            }
        }
    }

    return;
}
#endif

void ng_rpl_recv_DAO(ng_rpl_dao_t *dao, ng_ipv6_addr_t *src, uint16_t len)
{
    ng_rpl_instance_t *inst = NULL;
    ng_rpl_dodag_t *dodag = NULL;
    if ((inst = ng_rpl_instance_get(dao->instance_id)) == NULL) {
        DEBUG("RPL: DAO with unknown instance id (%d) received\n", dao->instance_id);
        return;
    }

    /* check if the D flag is set before accessing the DODAG id */
    if (!(dao->k_d_flags & (1 << 6))) {
        DEBUG("RPL: DAO with D flag unset - global instances not supported\n");
        return;
    }

    if ((dodag = ng_rpl_dodag_get(inst, &dao->dodag_id)) == NULL) {
        DEBUG("RPL: DAO with unknown DODAG id (%s)\n", ng_ipv6_addr_to_str(addr_str,
                    &dao->dodag_id, sizeof(addr_str)));
        return;
    }

    len -= (sizeof(ng_rpl_dao_t) + sizeof(ng_icmpv6_hdr_t));
    _parse_options(dodag, (ng_rpl_opt_t *) (dao + 1), len, src);

    /* send a DAO-ACK if K flag is set */
    if (dao->k_d_flags & (1 << 7)) {
        ng_rpl_send_DAO_ACK(dodag, src, dao->dao_sequence);
    }

    ng_rpl_delay_dao(dodag);
    return;
}

void ng_rpl_recv_DAO_ACK(ng_rpl_dao_ack_t *dao_ack)
{
    ng_rpl_instance_t *inst = NULL;
    ng_rpl_dodag_t *dodag = NULL;
    if ((inst = ng_rpl_instance_get(dao_ack->instance_id)) == NULL) {
        DEBUG("RPL: DAO-ACK with unknown instance id (%d) received\n", dao_ack->instance_id);
        return;
    }

    /* check if the D flag is set before accessing the DODAG id */
    if (!(dao_ack->d_reserved & (1 << 7))) {
        DEBUG("RPL: DAO with D flag unset - global instances not supported\n");
        return;
    }

    if ((dodag = ng_rpl_dodag_get(inst, &dao_ack->dodag_id)) == NULL) {
        DEBUG("RPL: DAO-ACK with unknown DODAG id (%s)\n", ng_ipv6_addr_to_str(addr_str,
                    &dao_ack->dodag_id, sizeof(addr_str)));
        return;
    }

    if ((dao_ack->status != 0) && (dao_ack->dao_sequence != dodag->dao_seq)) {
        return;
    }

    dodag->dao_ack_received = true;
    ng_rpl_long_delay_dao(dodag);
    return;
}

/**
 * @}
 */
