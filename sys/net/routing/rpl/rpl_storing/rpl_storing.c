/*
 * Copyright (C) 2013, 2014  INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @ingroup     rpl
 * @{
 *
 * @file        rpl_storing.c
 * @brief       RPL storing-mode
 *
 * Implementation of the storing mode of RPL.
 *
 * @author      Eric Engel <eric.engel@fu-berlin.de>
 * @author      Fabian Brandt <fabianbr@zedat.fu-berlin.de>
 */

#include "rpl/rpl_storing.h"
#include "msg.h"
#include "trickle.h"

#include "sixlowpan.h"
#include "net_help.h"

#define ENABLE_DEBUG    (0)
#if ENABLE_DEBUG
char addr_str_mode[IPV6_MAX_ADDR_STR_LEN];
#endif
#include "debug.h"

/* global variables */
rpl_dodag_t dodags[RPL_MAX_DODAGS];
const uint8_t p2p_lifetime_lookup[4] = { 1U, 4U, 16U, 64U };

/* in send buffer we need space fpr LL_HDR */
static uint8_t rpl_send_buffer[BUFFER_SIZE];

/* SEND BUFFERS */
static icmpv6_hdr_t *icmp_send_buf;
static struct rpl_dis_t *rpl_send_dis_buf;
static struct rpl_dao_ack_t *rpl_send_dao_ack_buf;
static ipv6_hdr_t *ipv6_send_buf;
static struct rpl_dio_t *rpl_send_dio_buf;
static struct rpl_dao_t *rpl_send_dao_buf;
static rpl_opt_dodag_conf_t *rpl_send_opt_dodag_conf_buf;
static rpl_opt_p2p_rdo_t *rpl_send_opt_p2p_rdo_buf;
static rpl_opt_target_t *rpl_send_opt_target_buf;
static rpl_opt_transit_t *rpl_send_opt_transit_buf;
static rpl_p2p_dro_t *rpl_send_dro_buf;

/* RECEIVE BUFFERS */
static ipv6_hdr_t *ipv6_buf;
static struct rpl_dio_t *rpl_dio_buf;
static struct rpl_dao_t *rpl_dao_buf;
static struct rpl_dao_ack_t *rpl_dao_ack_buf;
static rpl_opt_dodag_conf_t *rpl_opt_dodag_conf_buf;
static rpl_opt_target_t *rpl_opt_target_buf;
static rpl_opt_transit_t *rpl_opt_transit_buf;
static rpl_opt_p2p_rdo_t *rpl_opt_p2p_rdo_buf;
static struct rpl_dis_t *rpl_dis_buf;
static rpl_opt_t *rpl_opt_buf;
static rpl_opt_solicited_t *rpl_opt_solicited_buf;

/*  SEND BUFFERS */
static icmpv6_hdr_t *get_rpl_send_icmpv6_buf(uint8_t ext_len)
{
    return ((icmpv6_hdr_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ext_len]));
}

static struct rpl_dao_ack_t *get_rpl_send_dao_ack_buf(void)
{
    return ((struct rpl_dao_ack_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN]));
}

static struct rpl_dis_t *get_rpl_send_dis_buf(void)
{
    return ((struct rpl_dis_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN]));
}

static ipv6_hdr_t *get_rpl_send_ipv6_buf(void)
{
    return ((ipv6_hdr_t *) & (rpl_send_buffer[0]));
}

static uint8_t *get_rpl_send_payload_buf(uint8_t ext_len)
{
    return &(rpl_send_buffer[IPV6_HDR_LEN + ext_len]);
}

static struct rpl_dio_t *get_rpl_send_dio_buf(void)
{
    return ((struct rpl_dio_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN]));
}

static struct rpl_dao_t *get_rpl_send_dao_buf(void)
{
    return ((struct rpl_dao_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN]));
}

static rpl_opt_dodag_conf_t *get_rpl_send_opt_dodag_conf_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_dodag_conf_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_opt_target_t *get_rpl_send_opt_target_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_target_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_opt_transit_t *get_rpl_send_opt_transit_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_transit_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_opt_p2p_rdo_t *get_rpl_send_opt_p2p_rdo_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_p2p_rdo_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_p2p_dro_t *get_rpl_send_dro_buf(void)
{
    return ((rpl_p2p_dro_t *) & (rpl_send_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN]));
}


/* RECEIVE BUFFERS */
static ipv6_hdr_t *get_rpl_ipv6_buf(void)
{
    return ((ipv6_hdr_t *) & (rpl_buffer[0]));
}

static rpl_opt_target_t *get_rpl_opt_target_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_target_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_opt_transit_t *get_rpl_opt_transit_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_transit_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_opt_dodag_conf_t *get_rpl_opt_dodag_conf_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_dodag_conf_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static struct rpl_dio_t *get_rpl_dio_buf(void)
{
    return ((struct rpl_dio_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN]));
}

static struct rpl_dao_t *get_rpl_dao_buf(void)
{
    return ((struct rpl_dao_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN]));
}

static struct rpl_dao_ack_t *get_rpl_dao_ack_buf(void)
{
    return ((struct rpl_dao_ack_t *) & (buffer[(LL_HDR_LEN + IPV6_HDR_LEN + ICMPV6_HDR_LEN)]));
}

static struct rpl_dis_t *get_rpl_dis_buf(void)
{
    return ((struct rpl_dis_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN]));
}

static rpl_opt_t *get_rpl_opt_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_opt_solicited_t *get_rpl_opt_solicited_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_solicited_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_opt_p2p_rdo_t *get_rpl_opt_p2p_rdo_buf(uint8_t rpl_msg_len)
{
    return ((rpl_opt_p2p_rdo_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

static rpl_p2p_dro_t *get_rpl_p2p_dro_buf(uint8_t rpl_msg_len)
{
    return ((rpl_p2p_dro_t *) & (rpl_buffer[IPV6_HDR_LEN + ICMPV6_HDR_LEN + rpl_msg_len]));
}

void rpl_init_mode(ipv6_addr_t *init_address)
{
    memcpy(&my_address, init_address, sizeof(ipv6_addr_t));
}

void rpl_init_p2p_mode(uint8_t instanceid, uint8_t reply, uint8_t hop_by_hop, uint8_t no_of_routes,
        uint8_t compr, uint8_t lifetime, uint8_t maxrank_nexthop, ipv6_addr_t target)
{
    rpl_instance_t *inst;
    rpl_dodag_t *dodag;

    inst = rpl_new_instance(instanceid);

    if (inst == NULL) {
        DEBUGF("Error - No memory for another RPL instance\n");
        return;
    }

    inst->joined = 1;

    dodag = rpl_new_dodag(instanceid, &my_address);

    if (dodag != NULL) {
        dodag->of = (struct rpl_of_t *) rpl_get_of_for_ocp(RPL_DEFAULT_OCP);
        dodag->instance = inst;
        dodag->mop = RPL_P2P_MODE;
        dodag->dtsn = 0;
        dodag->prf = 0;
        dodag->dio_interval_doubling = DEFAULT_DIO_INTERVAL_DOUBLINGS;
        dodag->dio_min = DEFAULT_DIO_INTERVAL_MIN;
        dodag->dio_redundancy = DEFAULT_DIO_REDUNDANCY_CONSTANT;
        dodag->maxrankincrease = 0;
        dodag->minhoprankincrease = (uint16_t)DEFAULT_MIN_HOP_RANK_INCREASE;
        dodag->default_lifetime = (uint8_t)RPL_DEFAULT_LIFETIME;
        dodag->lifetime_unit = RPL_LIFETIME_UNIT;
        dodag->version = 0;
        dodag->grounded = 1;
        dodag->node_status = (uint8_t) ROOT_NODE;
        dodag->my_rank = RPL_ROOT_RANK;
        dodag->joined = 1;
        dodag->my_preferred_parent = NULL;
        dodag->i_am_root = 1;
        dodag->is_p2p = 1;
        dodag->p2p_reply = reply;
        dodag->p2p_hop_by_hop = hop_by_hop;
        dodag->p2p_no_of_routes = no_of_routes;
        dodag->p2p_compr = compr;
        dodag->p2p_lifetime = lifetime;
        dodag->p2p_lifetime_sec = p2p_lifetime_lookup[lifetime];
        dodag->p2p_maxrank_nexthop = maxrank_nexthop;
        dodag->p2p_target = target;
    }
    else {
        DEBUGF("Error - could not generate DODAG\n");
        return;
    }

    start_trickle(rpl_process_pid, &dodag->trickle, RPL_MSG_TYPE_TRICKLE_INTERVAL, RPL_MSG_TYPE_TRICKLE_CALLBACK, (1 << dodag->dio_min), dodag->dio_interval_doubling, dodag->dio_redundancy);
    DEBUGF("P2P ROOT INIT FINISHED\n");
}

void rpl_init_root_mode(uint8_t instanceid)
{
    rpl_instance_t *inst;
    rpl_dodag_t *dodag;

    inst = rpl_new_instance(instanceid);

    if (inst == NULL) {
        DEBUGF("Error - No memory for another RPL instance\n");
        return;
    }

    inst->joined = 1;

    dodag = rpl_new_dodag(instanceid, &my_address);

    if (dodag != NULL) {
        dodag->of = (struct rpl_of_t *) rpl_get_of_for_ocp(RPL_DEFAULT_OCP);
        dodag->instance = inst;
        dodag->mop = RPL_DEFAULT_MOP;
        dodag->dtsn = 1;
        dodag->prf = 0;
        dodag->dio_interval_doubling = DEFAULT_DIO_INTERVAL_DOUBLINGS;
        dodag->dio_min = DEFAULT_DIO_INTERVAL_MIN;
        dodag->dio_redundancy = DEFAULT_DIO_REDUNDANCY_CONSTANT;
        dodag->maxrankincrease = 0;
        dodag->minhoprankincrease = (uint16_t)DEFAULT_MIN_HOP_RANK_INCREASE;
        dodag->default_lifetime = (uint8_t)RPL_DEFAULT_LIFETIME;
        dodag->lifetime_unit = RPL_LIFETIME_UNIT;
        dodag->version = RPL_COUNTER_INIT;
        dodag->grounded = RPL_GROUNDED;
        dodag->node_status = (uint8_t) ROOT_NODE;
        dodag->my_rank = RPL_ROOT_RANK;
        dodag->joined = 1;
        dodag->my_preferred_parent = NULL;
    }
    else {
        DEBUGF("Error - could not generate DODAG\n");
        return;
    }

    dodag->i_am_root = 1;
    start_trickle(rpl_process_pid, &dodag->trickle, RPL_MSG_TYPE_TRICKLE_INTERVAL, RPL_MSG_TYPE_TRICKLE_CALLBACK, (1 << dodag->dio_min), dodag->dio_interval_doubling, dodag->dio_redundancy);
    DEBUGF("ROOT INIT FINISHED\n");

}

uint8_t rpl_is_root_mode(void)
{
    for (uint8_t i = 0; i < RPL_MAX_DODAGS; i++) {
        if (dodags[i].i_am_root) {
            return 1;
        }
    }

    return 0;
}

void rpl_send_DIO_mode(ipv6_addr_t *destination, rpl_dodag_t *mydodag)
{
    icmp_send_buf = get_rpl_send_icmpv6_buf(ipv6_ext_hdr_len);

    if (mydodag == NULL) {
        DEBUGF("Error - trying to send DIO without being part of a dodag.\n");
        return;
    }

    if (mydodag->node_status == LEAF_NODE) {
        DEBUGF("Leaf Node - do not send DIOs\n");
        return;
    }

    icmp_send_buf->type = ICMPV6_TYPE_RPL_CONTROL;
    icmp_send_buf->code = ICMP_CODE_DIO;

    rpl_send_dio_buf = get_rpl_send_dio_buf();
    memset(rpl_send_dio_buf, 0, sizeof(*rpl_send_dio_buf));

    DEBUGF("Sending DIO with ");
    rpl_send_dio_buf->rpl_instanceid = mydodag->instance->id;
    DEBUG("instance %02X ", rpl_send_dio_buf->rpl_instanceid);
    rpl_send_dio_buf->version_number = mydodag->version;
    rpl_send_dio_buf->rank = mydodag->my_rank;
    DEBUG("rank %04X\n", rpl_send_dio_buf->rank);
    rpl_send_dio_buf->g_mop_prf = (mydodag->grounded << RPL_GROUNDED_SHIFT) |
            (mydodag->mop << RPL_MOP_SHIFT) | mydodag->prf;
    rpl_send_dio_buf->dtsn = mydodag->dtsn;
    rpl_send_dio_buf->flags = 0;
    rpl_send_dio_buf->reserved = 0;
    rpl_send_dio_buf->dodagid = mydodag->dodag_id;

    int opt_hdr_len = 0;
    /* DODAG configuration option */
    rpl_send_opt_dodag_conf_buf = get_rpl_send_opt_dodag_conf_buf(DIO_BASE_LEN);
    rpl_send_opt_dodag_conf_buf->type = RPL_OPT_DODAG_CONF;
    rpl_send_opt_dodag_conf_buf->length = (RPL_OPT_DODAG_CONF_LEN - RPL_OPT_LEN);
    rpl_send_opt_dodag_conf_buf->flags_a_pcs = 0;
    rpl_send_opt_dodag_conf_buf->DIOIntDoubl = mydodag->dio_interval_doubling;
    rpl_send_opt_dodag_conf_buf->DIOIntMin = mydodag->dio_min;
    rpl_send_opt_dodag_conf_buf->DIORedun = mydodag->dio_redundancy;
    rpl_send_opt_dodag_conf_buf->MaxRankIncrease = mydodag->maxrankincrease;
    rpl_send_opt_dodag_conf_buf->MinHopRankIncrease = mydodag->minhoprankincrease;
    rpl_send_opt_dodag_conf_buf->ocp = mydodag->of->ocp;
    rpl_send_opt_dodag_conf_buf->reserved = 0;
    rpl_send_opt_dodag_conf_buf->default_lifetime = mydodag->default_lifetime;
    rpl_send_opt_dodag_conf_buf->lifetime_unit = mydodag->lifetime_unit;

    opt_hdr_len += RPL_OPT_DODAG_CONF_LEN;

    if (mydodag->is_p2p && !rpl_equal_id(&mydodag->p2p_target, &my_address)) {
        rpl_send_opt_p2p_rdo_buf = get_rpl_send_opt_p2p_rdo_buf(DIO_BASE_LEN + opt_hdr_len);
        rpl_send_opt_p2p_rdo_buf->type = RPL_OPT_P2P_RDO;
        rpl_send_opt_p2p_rdo_buf->reply = mydodag->p2p_reply;
        rpl_send_opt_p2p_rdo_buf->hop_by_hop = mydodag->p2p_hop_by_hop;
        rpl_send_opt_p2p_rdo_buf->no_of_routes = mydodag->p2p_no_of_routes;
        rpl_send_opt_p2p_rdo_buf->compr = mydodag->p2p_compr;
        rpl_send_opt_p2p_rdo_buf->lifetime = mydodag->p2p_lifetime;
        rpl_send_opt_p2p_rdo_buf->target = mydodag->p2p_target;
        rpl_send_opt_p2p_rdo_buf->length = RPL_OPT_P2P_RDO_LEN;

        ipv6_addr_t *addresses = (ipv6_addr_t *) (rpl_send_opt_p2p_rdo_buf + 1);
        uint8_t i = 0;

        if(!mydodag->i_am_root) {
            for (i = 0; i < RPL_P2P_RDO_MAX_ADDRESSES; i++) {
                if (mydodag->p2p_addresses[i].uint32[3] == 0) {
                    break;
                }
                memcpy(addresses++, &mydodag->p2p_addresses[i], sizeof(ipv6_addr_t));
                rpl_send_opt_p2p_rdo_buf->length += sizeof(ipv6_addr_t);
            }

            if (i < RPL_P2P_RDO_MAX_ADDRESSES) {
                memcpy(addresses++, &my_address, sizeof(ipv6_addr_t));
                rpl_send_opt_p2p_rdo_buf->length += sizeof(ipv6_addr_t);
            }
        }
        opt_hdr_len += rpl_send_opt_p2p_rdo_buf->length + RPL_OPT_LEN;
    }

    uint16_t plen = ICMPV6_HDR_LEN + DIO_BASE_LEN + opt_hdr_len;
    rpl_send(destination, (uint8_t *)icmp_send_buf, plen, IPV6_PROTO_NUM_ICMPV6);
}

void rpl_send_DAO_mode(ipv6_addr_t *destination, uint8_t lifetime, bool default_lifetime, uint8_t start_index, rpl_dodag_t *my_dodag)
{
    if (my_dodag->i_am_root) {
        return;
    }

    if (my_dodag == NULL) {
        DEBUGF("send_DAO: I have no my_dodag\n");
        return;
    }

    if (destination == NULL) {
        if (my_dodag->my_preferred_parent == NULL) {
            DEBUGF("send_DAO: my_dodag has no my_preferred_parent\n");
            return;
        }

        destination = &my_dodag->my_preferred_parent->addr;
    }

    if (default_lifetime) {
        lifetime = my_dodag->default_lifetime;
    }

    icmp_send_buf  = get_rpl_send_icmpv6_buf(ipv6_ext_hdr_len);

    icmp_send_buf->type = ICMPV6_TYPE_RPL_CONTROL;
    icmp_send_buf->code = ICMP_CODE_DAO;

    rpl_send_dao_buf = get_rpl_send_dao_buf();
    memset(rpl_send_dao_buf, 0, sizeof(*rpl_send_dao_buf));
    rpl_send_dao_buf->rpl_instanceid = my_dodag->instance->id;
    rpl_send_dao_buf->k_d_flags = 0x00;
    rpl_send_dao_buf->dao_sequence = my_dodag->dao_seq;
    uint16_t opt_len = 0;
    rpl_send_opt_target_buf = get_rpl_send_opt_target_buf(DAO_BASE_LEN);
    /* add all targets from routing table as targets */
    uint8_t entries = 0;
    uint8_t continue_index = 0;

    for (uint8_t i = start_index; i < rpl_max_routing_entries; i++) {
        if (rpl_get_routing_table()[i].used) {
            rpl_send_opt_target_buf->type = RPL_OPT_TARGET;
            rpl_send_opt_target_buf->length = (RPL_OPT_TARGET_LEN - RPL_OPT_LEN);
            rpl_send_opt_target_buf->flags = 0x00;
            rpl_send_opt_target_buf->prefix_length = RPL_DODAG_ID_LEN;
            memcpy(&rpl_send_opt_target_buf->target, &rpl_get_routing_table()[i].address,
                    sizeof(ipv6_addr_t));
            opt_len += RPL_OPT_TARGET_LEN;
            rpl_send_opt_transit_buf = get_rpl_send_opt_transit_buf(DAO_BASE_LEN + opt_len);
            rpl_send_opt_transit_buf->type = RPL_OPT_TRANSIT;
            rpl_send_opt_transit_buf->length = (RPL_OPT_TRANSIT_LEN - RPL_OPT_LEN - sizeof(ipv6_addr_t));
            rpl_send_opt_transit_buf->e_flags = 0x00;
            rpl_send_opt_transit_buf->path_control = 0x00; /* not used */
            rpl_send_opt_transit_buf->path_sequence = 0x00; /* not used */
            rpl_send_opt_transit_buf->path_lifetime = lifetime;
            opt_len += (RPL_OPT_TRANSIT_LEN - sizeof(ipv6_addr_t));
            rpl_send_opt_target_buf = get_rpl_send_opt_target_buf(DAO_BASE_LEN + opt_len);
            entries++;
        }

        /* Split DAO, so packages don't get too big.
         * The value 5 is based on experience. */
        if (entries >= 5) {
            continue_index = i + 1;
            break;
        }
    }

    /* add own address */
    rpl_send_opt_target_buf->type = RPL_OPT_TARGET;
    rpl_send_opt_target_buf->length = (RPL_OPT_TARGET_LEN - RPL_OPT_LEN);
    rpl_send_opt_target_buf->flags = 0x00;
    rpl_send_opt_target_buf->prefix_length = RPL_DODAG_ID_LEN;
    memcpy(&rpl_send_opt_target_buf->target, &my_address, sizeof(ipv6_addr_t));
    opt_len += RPL_OPT_TARGET_LEN;

    rpl_send_opt_transit_buf = get_rpl_send_opt_transit_buf(DAO_BASE_LEN + opt_len);
    rpl_send_opt_transit_buf->type = RPL_OPT_TRANSIT;
    rpl_send_opt_transit_buf->length = (RPL_OPT_TRANSIT_LEN - RPL_OPT_LEN - sizeof(ipv6_addr_t));
    rpl_send_opt_transit_buf->e_flags = 0x00;
    rpl_send_opt_transit_buf->path_control = 0x00;
    rpl_send_opt_transit_buf->path_sequence = 0x00;
    rpl_send_opt_transit_buf->path_lifetime = lifetime;
    opt_len += (RPL_OPT_TRANSIT_LEN - sizeof(ipv6_addr_t));

    uint16_t plen = ICMPV6_HDR_LEN + DAO_BASE_LEN + opt_len;
    rpl_send(destination, (uint8_t *)icmp_send_buf, plen, IPV6_PROTO_NUM_ICMPV6);

    if (continue_index > 1) {
        rpl_send_DAO(destination, lifetime, default_lifetime, continue_index, my_dodag);
    }
}

void rpl_send_DIS_mode(ipv6_addr_t *destination)
{
    icmp_send_buf = get_rpl_send_icmpv6_buf(ipv6_ext_hdr_len);

    icmp_send_buf->type = ICMPV6_TYPE_RPL_CONTROL;
    icmp_send_buf->code = ICMP_CODE_DIS;

    rpl_send_dis_buf = get_rpl_send_dis_buf();
    rpl_send_dis_buf->flags = 0;
    rpl_send_dis_buf->reserved = 0;

    uint16_t plen = ICMPV6_HDR_LEN + DIS_BASE_LEN;
    rpl_send(destination, (uint8_t *)icmp_send_buf, plen, IPV6_PROTO_NUM_ICMPV6);
}

void rpl_send_DAO_ACK_mode(ipv6_addr_t *destination, rpl_dodag_t *my_dodag)
{
    if (my_dodag == NULL) {
        return;
    }

    icmp_send_buf = get_rpl_send_icmpv6_buf(ipv6_ext_hdr_len);

    icmp_send_buf->type = ICMPV6_TYPE_RPL_CONTROL;
    icmp_send_buf->code = ICMP_CODE_DAO_ACK;

    rpl_send_dao_ack_buf = get_rpl_send_dao_ack_buf();
    rpl_send_dao_ack_buf->rpl_instanceid = my_dodag->instance->id;
    rpl_send_dao_ack_buf->d_reserved = 0;
    rpl_send_dao_ack_buf->dao_sequence = my_dodag->dao_seq;
    rpl_send_dao_ack_buf->status = 0;

    uint16_t plen = ICMPV6_HDR_LEN + DAO_ACK_LEN;
    rpl_send(destination, (uint8_t *)icmp_send_buf, plen, IPV6_PROTO_NUM_ICMPV6);
}

void rpl_send_DRO_mode(rpl_dodag_t *mydodag)
{
    icmp_send_buf = get_rpl_send_icmpv6_buf(ipv6_ext_hdr_len);

    if (mydodag == NULL) {
        DEBUGF("Error - No DODAG.\n");
        return;
    }

    icmp_send_buf->type = ICMPV6_TYPE_RPL_CONTROL;
    icmp_send_buf->code = ICMP_CODE_DRO;

    rpl_send_dro_buf = get_rpl_send_dro_buf();
    memset(rpl_send_dro_buf, 0, sizeof(rpl_p2p_dro_t));

    rpl_send_dro_buf->instance_id = mydodag->instance->id;
    rpl_send_dro_buf->version = 0;
    RPL_P2P_SET(rpl_send_dro_buf->flags_reserved, 1, RDO_STOP);
    RPL_P2P_SET(rpl_send_dro_buf->flags_reserved, 0, RDO_ACK);
    RPL_P2P_SET(rpl_send_dro_buf->flags_reserved, 0, RDO_SEQ_NO);
    rpl_send_dro_buf->dodagid = mydodag->dodag_id;

    int opt_hdr_len = 0;

    rpl_send_opt_p2p_rdo_buf = get_rpl_send_opt_p2p_rdo_buf(DRO_BASE_LEN);
    rpl_send_opt_p2p_rdo_buf->type = RPL_OPT_P2P_RDO;
    rpl_send_opt_p2p_rdo_buf->reply = mydodag->p2p_reply;
    rpl_send_opt_p2p_rdo_buf->hop_by_hop = mydodag->p2p_hop_by_hop;
    rpl_send_opt_p2p_rdo_buf->no_of_routes = mydodag->p2p_no_of_routes;
    rpl_send_opt_p2p_rdo_buf->compr = mydodag->p2p_compr;
    rpl_send_opt_p2p_rdo_buf->lifetime = mydodag->p2p_lifetime;
    rpl_send_opt_p2p_rdo_buf->target = mydodag->p2p_target;
    rpl_send_opt_p2p_rdo_buf->length = RPL_OPT_P2P_RDO_LEN;

    ipv6_addr_t *addresses = (ipv6_addr_t *) (rpl_send_opt_p2p_rdo_buf + 1);
    for (uint8_t i = 0; i < RPL_P2P_RDO_MAX_ADDRESSES; i++) {
        if (mydodag->p2p_addresses[i].uint32[3] != 0) {
            memcpy(addresses++, &mydodag->p2p_addresses[i], sizeof(ipv6_addr_t));
            rpl_send_opt_p2p_rdo_buf->length += sizeof(ipv6_addr_t);
        }
    }
    opt_hdr_len += rpl_send_opt_p2p_rdo_buf->length + RPL_OPT_LEN;

    uint16_t plen = ICMPV6_HDR_LEN + DRO_BASE_LEN + opt_hdr_len;
    rpl_send(&mcast, (uint8_t *)icmp_send_buf, plen, IPV6_PROTO_NUM_ICMPV6);
}

void rpl_recv_DIO_mode(void)
{
    ipv6_buf = get_rpl_ipv6_buf();

    rpl_dio_buf = get_rpl_dio_buf();
    DEBUGF("instance %04X ", rpl_dio_buf->rpl_instanceid);
    DEBUGF("rank %04X\n", rpl_dio_buf->rank);
    int len = DIO_BASE_LEN;

    rpl_instance_t *dio_inst = rpl_get_instance(rpl_dio_buf->rpl_instanceid);

    if (dio_inst == NULL) {
        dio_inst = rpl_new_instance(rpl_dio_buf->rpl_instanceid);

        if (dio_inst == NULL) {
            DEBUGF("Failed to create a new RPL instance!\n");
            return;
        }
    }

    rpl_dodag_t dio_dodag;
    memset(&dio_dodag, 0, sizeof(dio_dodag));

    memcpy(&dio_dodag.dodag_id, &rpl_dio_buf->dodagid, sizeof(dio_dodag.dodag_id));
    dio_dodag.dtsn = rpl_dio_buf->dtsn;
    dio_dodag.mop = ((rpl_dio_buf->g_mop_prf >> RPL_MOP_SHIFT) & RPL_SHIFTED_MOP_MASK);
    dio_dodag.grounded = rpl_dio_buf->g_mop_prf >> RPL_GROUNDED_SHIFT;
    dio_dodag.prf = (rpl_dio_buf->g_mop_prf & RPL_PRF_MASK);
    dio_dodag.version = rpl_dio_buf->version_number;
    dio_dodag.instance = dio_inst;

    uint8_t has_dodag_conf_opt = 0;

    /* Parse until all options are consumed.
     * ipv6_buf->length contains the packet length minus ipv6 and
     * icmpv6 header, so only ICMPV6_HDR_LEN remains to be
     * subtracted.  */
    while (len < (NTOHS(ipv6_buf->length) - ICMPV6_HDR_LEN)) {
        DEBUGF("parsing DIO options\n");
        rpl_opt_buf = get_rpl_opt_buf(len);

        switch (rpl_opt_buf->type) {

            case (RPL_OPT_PAD1): {
                len += 1;
                break;
            }

            case (RPL_OPT_PADN): {
                len += rpl_opt_buf->length;
                break;
            }

            case (RPL_OPT_DAG_METRIC_CONTAINER): {
                len += rpl_opt_buf->length;
                break;
            }

            case (RPL_OPT_ROUTE_INFO): {
                len += rpl_opt_buf->length;
                break;
            }

            case (RPL_OPT_DODAG_CONF): {
                has_dodag_conf_opt = 1;

                if (rpl_opt_buf->length != (RPL_OPT_DODAG_CONF_LEN - RPL_OPT_LEN)) {
                    DEBUGF("DODAG configuration is malformed.\n");
                    /* error malformed */
                    return;
                }

                rpl_opt_dodag_conf_buf = get_rpl_opt_dodag_conf_buf(len);
                dio_dodag.dio_interval_doubling = rpl_opt_dodag_conf_buf->DIOIntDoubl;
                dio_dodag.dio_min = rpl_opt_dodag_conf_buf->DIOIntMin;
                dio_dodag.dio_redundancy = rpl_opt_dodag_conf_buf->DIORedun;
                dio_dodag.maxrankincrease = rpl_opt_dodag_conf_buf->MaxRankIncrease;
                dio_dodag.minhoprankincrease = rpl_opt_dodag_conf_buf->MinHopRankIncrease;
                dio_dodag.default_lifetime = rpl_opt_dodag_conf_buf->default_lifetime;
                dio_dodag.lifetime_unit = rpl_opt_dodag_conf_buf->lifetime_unit;
                dio_dodag.of = (struct rpl_of_t *) rpl_get_of_for_ocp(rpl_opt_dodag_conf_buf->ocp);
                len += RPL_OPT_DODAG_CONF_LEN;
                break;
            }

            case (RPL_OPT_PREFIX_INFO): {
                if (rpl_opt_buf->length != (RPL_OPT_PREFIX_INFO_LEN - RPL_OPT_LEN)) {
                    /* error malformed */
                    return;
                }

                len += RPL_OPT_PREFIX_INFO_LEN;
                break;
            }

            case (RPL_OPT_P2P_RDO): {
                dio_dodag.is_p2p = 1;
                rpl_opt_p2p_rdo_buf = get_rpl_opt_p2p_rdo_buf(len);
                dio_dodag.p2p_reply = rpl_opt_p2p_rdo_buf->reply;
                dio_dodag.p2p_hop_by_hop = rpl_opt_p2p_rdo_buf->hop_by_hop;
                dio_dodag.p2p_no_of_routes = rpl_opt_p2p_rdo_buf->no_of_routes;
                dio_dodag.p2p_compr = rpl_opt_p2p_rdo_buf->compr;
                dio_dodag.p2p_lifetime = rpl_opt_p2p_rdo_buf->lifetime;
                dio_dodag.p2p_maxrank_nexthop = rpl_opt_p2p_rdo_buf->maxrank_nexthop;
                dio_dodag.p2p_target = rpl_opt_p2p_rdo_buf->target;

                ipv6_addr_t *addresses = (ipv6_addr_t *) (rpl_opt_p2p_rdo_buf + 1);
                uint8_t j = 0;
                for (uint8_t i = RPL_OPT_P2P_RDO_LEN; i < rpl_opt_p2p_rdo_buf->length; i += sizeof(ipv6_addr_t)) {
                    memcpy(&dio_dodag.p2p_addresses[j++], addresses++, sizeof(ipv6_addr_t));
                }

                len += RPL_OPT_LEN + rpl_opt_p2p_rdo_buf->length;
                break;
            }

            default:
                DEBUGF("[Error] Unsupported DIO option\n");
                return;
        }
    }

    /* handle packet content... */
    rpl_dodag_t *my_dodag = rpl_get_joined_dodag(dio_inst->id);

    if (my_dodag != NULL && !my_dodag->i_am_root && !rpl_equal_id(&my_dodag->dodag_id, &dio_dodag.dodag_id)) {
        rpl_parent_t tmp_parent;
        tmp_parent.rank = rpl_dio_buf->rank;
        tmp_parent.dodag = &dio_dodag;
        dio_dodag.my_preferred_parent = &tmp_parent;
        dio_dodag.my_rank = dio_dodag.of->calc_rank(&tmp_parent, tmp_parent.rank);
        if (my_dodag != my_dodag->of->which_dodag(my_dodag, &dio_dodag)) {
            rpl_leave_dodag(my_dodag);
            my_dodag = NULL;
        }
    }

    if (my_dodag == NULL) {
        if (!has_dodag_conf_opt) {
            DEBUGF("send DIS\n");
            rpl_send_DIS(&ipv6_buf->srcaddr);
        }

        if (rpl_dio_buf->rank < ROOT_RANK) {
            DEBUGF("DIO with Rank < ROOT_RANK\n");
        }

        if (dio_dodag.mop != RPL_DEFAULT_MOP) {
            DEBUGF("Required MOP not supported\n");
        }

        if (dio_dodag.of == NULL) {
            DEBUGF("Required objective function not supported\n");
        }

        if (rpl_dio_buf->rank != INFINITE_RANK) {
            DEBUGF("Will join DODAG\n");
            rpl_join_dodag(&dio_dodag, &ipv6_buf->srcaddr, rpl_dio_buf->rank);
        }
        else {
            DEBUGF("Cannot access DODAG because of DIO with infinite rank\n");
        }

        return;
    }

    if (my_dodag->is_p2p && my_dodag->p2p_lifetime_sec < 1) {
        rpl_leave_dodag(my_dodag);
        return;
    }

    if (rpl_equal_id(&my_dodag->dodag_id, &dio_dodag.dodag_id)) {
        /* "our" DODAG */
        if (RPL_COUNTER_GREATER_THAN(dio_dodag.version, my_dodag->version)) {
            if (my_dodag->my_rank == ROOT_RANK) {
                DEBUGF("[Warning] Inconsistent Dodag Version\n");
                my_dodag->version = RPL_COUNTER_INCREMENT(dio_dodag.version);
                reset_trickletimer(&my_dodag->trickle);
            }
            else {
                DEBUGF("my dodag has no preferred_parent yet - seems to be odd since I have a parent.\n");
                rpl_global_repair(&dio_dodag, &ipv6_buf->srcaddr, rpl_dio_buf->rank);
            }

            return;
        }
        else if (RPL_COUNTER_GREATER_THAN(my_dodag->version, dio_dodag.version)) {
            /* ein Knoten hat noch eine kleinere Versionsnummer -> mehr DIOs senden */
            reset_trickletimer(&my_dodag->trickle);
            return;
        }
    }

    /* version matches, DODAG matches */
    if (rpl_dio_buf->rank == INFINITE_RANK) {
        reset_trickletimer(&my_dodag->trickle);
    }

    /* We are root, all done!*/
    if (my_dodag->my_rank == ROOT_RANK) {
        if (rpl_dio_buf->rank != INFINITE_RANK) {
            trickle_increment_counter(&my_dodag->trickle);
        }

        return;
    }

    /*********************  Parent Handling *********************/

    rpl_parent_t *parent;
    parent = rpl_find_parent(my_dodag->instance->id, &ipv6_buf->srcaddr);

    if (parent == NULL) {
        /* add new parent candidate */
        parent = rpl_new_parent(my_dodag, &ipv6_buf->srcaddr, rpl_dio_buf->rank);

        if (parent == NULL) {
            return;
        }
    }
    else {
        /* DIO OK */
        trickle_increment_counter(&my_dodag->trickle);
    }

    /* update parent rank */
    parent->rank = rpl_dio_buf->rank;
    rpl_parent_update(parent, my_dodag);

    if (my_dodag->my_preferred_parent == NULL) {
        rpl_leave_dodag(my_dodag);
        DEBUGF("My dodag has no preferred_parent yet - seems to be odd since I have a parent...\n");
    }
    else if (rpl_equal_id(&parent->addr, &my_dodag->my_preferred_parent->addr) &&
            (parent->dtsn != rpl_dio_buf->dtsn)) {
        delay_dao(my_dodag);
    }

    if (my_dodag->is_p2p) {
        parent->dtsn = 0;
        if (rpl_equal_id(&my_dodag->p2p_target, &my_address)) {
            rpl_send_DRO(my_dodag);
        }
    }
    else {
        parent->dtsn = rpl_dio_buf->dtsn;
    }

}

void rpl_recv_DAO_mode(void)
{
    ipv6_buf = get_rpl_ipv6_buf();
    rpl_dao_buf = get_rpl_dao_buf();
    DEBUG("instance %04X ", rpl_dao_buf->rpl_instanceid);
    DEBUG("sequence %04X\n", rpl_dao_buf->dao_sequence);

    rpl_dodag_t *my_dodag = rpl_get_joined_dodag(rpl_dao_buf->rpl_instanceid);

    if (my_dodag == NULL) {
        DEBUG("[Error] got DAO although not a DODAG\n");
        return;
    }

    int len = DAO_BASE_LEN;
    uint8_t increment_seq = 0;

    while (len < (NTOHS(ipv6_buf->length) - ICMPV6_HDR_LEN)) {
        rpl_opt_buf = get_rpl_opt_buf(len);

        switch (rpl_opt_buf->type) {

            case (RPL_OPT_PAD1): {
                len += 1;
                break;
            }

            case (RPL_OPT_PADN): {
                len += (rpl_opt_buf->length + RPL_OPT_LEN);
                break;
            }

            case (RPL_OPT_DAG_METRIC_CONTAINER): {
                len += (rpl_opt_buf->length + RPL_OPT_LEN);
                break;
            }

            case (RPL_OPT_TARGET): {
                rpl_opt_target_buf = get_rpl_opt_target_buf(len);

                if (rpl_opt_target_buf->prefix_length != RPL_DODAG_ID_LEN) {
                    DEBUGF("prefixes are not supported yet\n");
                    break;
                }

                len += (rpl_opt_target_buf->length + RPL_OPT_LEN);
                rpl_opt_transit_buf = get_rpl_opt_transit_buf(len);

                if (rpl_opt_transit_buf->type != RPL_OPT_TRANSIT) {
                    DEBUGF("[Error] - no transit information for target option type = %d\n",
                            rpl_opt_transit_buf->type);
                    break;
                }

                len += (rpl_opt_transit_buf->length + RPL_OPT_LEN - sizeof(ipv6_addr_t));
                /* route lifetime seconds = (DAO lifetime) * (Unit Lifetime) */

                DEBUG("Adding routing information: Target: %s, Source: %s, Lifetime: %u\n",
                      ipv6_addr_to_str(addr_str_mode, IPV6_MAX_ADDR_STR_LEN, &rpl_opt_target_buf->target),
                      ipv6_addr_to_str(addr_str_mode, IPV6_MAX_ADDR_STR_LEN, &ipv6_buf->srcaddr),
                      (rpl_opt_transit_buf->path_lifetime * my_dodag->lifetime_unit));
                rpl_add_routing_entry(&rpl_opt_target_buf->target, &ipv6_buf->srcaddr,
                        rpl_opt_transit_buf->path_lifetime * my_dodag->lifetime_unit, my_dodag);
                increment_seq = 1;
                break;
            }

            case (RPL_OPT_TRANSIT): {
                len += (rpl_opt_buf->length + RPL_OPT_LEN);
                break;
            }

            case (RPL_OPT_TARGET_DESC): {
                len += (rpl_opt_buf->length + RPL_OPT_LEN);
                break;
            }

            default:
                return;
        }
    }

    rpl_send_DAO_ACK(&ipv6_buf->srcaddr, my_dodag);

    if (increment_seq) {
        RPL_COUNTER_INCREMENT(my_dodag->dao_seq);
        delay_dao(my_dodag);
    }
}

void rpl_recv_DIS_mode(void)
{
    ipv6_buf = get_rpl_ipv6_buf();
    rpl_dis_buf = get_rpl_dis_buf();
    int len = DIS_BASE_LEN;
    rpl_dodag_t *dodag, *end;
    uint8_t options_missing = 1;

    while (len < (NTOHS(ipv6_buf->length) - ICMPV6_HDR_LEN)) {
        rpl_opt_buf = get_rpl_opt_buf(len);

        switch (rpl_opt_buf->type) {
            case (RPL_OPT_PAD1): {
                len += 1;
                break;
            }

            case (RPL_OPT_PADN): {
                len += (rpl_opt_buf->length + RPL_OPT_LEN);
                break;
            }

            case (RPL_OPT_SOLICITED_INFO): {
                options_missing = 0;
                len += RPL_OPT_SOLICITED_INFO_LEN;

                /* extract and check */
                if (rpl_opt_buf->length != (RPL_OPT_SOLICITED_INFO_LEN - RPL_OPT_LEN)) {
                    /* error malformed */
                    return;
                }

                rpl_opt_solicited_buf = get_rpl_opt_solicited_buf(len);

                for (dodag = &dodags[0], end = dodag + RPL_MAX_DODAGS; dodag < end; dodag++) {
                    if (dodag->used) {
                        if (rpl_opt_solicited_buf->VID_Flags & RPL_DIS_I_MASK) {
                            if (dodag->instance->id != rpl_opt_solicited_buf->rplinstanceid) {
                                continue;
                            }
                        }

                        if (rpl_opt_solicited_buf->VID_Flags & RPL_DIS_D_MASK) {
                            if (!rpl_equal_id(&dodag->dodag_id, &rpl_opt_solicited_buf->dodagid)) {
                                continue;
                            }
                        }

                        if (rpl_opt_solicited_buf->VID_Flags & RPL_DIS_V_MASK) {
                            if (dodag->version != rpl_opt_solicited_buf->version) {
                                continue;
                            }
                        }

                        rpl_send_DIO(&ipv6_buf->srcaddr, dodag);
                        reset_trickletimer(&dodag->trickle);
                    }
                }

                break;
            }

            default:
                return;
        }
    }

    if (options_missing) {
        for (dodag = &dodags[0], end = dodag + RPL_MAX_DODAGS; dodag < end; dodag++) {
            if (!dodag->is_p2p && dodag->joined) {
                rpl_send_DIO(&ipv6_buf->srcaddr, dodag);
                reset_trickletimer(&dodag->trickle);
            }
        }
    }
}

void rpl_recv_dao_ack_mode(void)
{
    rpl_dao_ack_buf = get_rpl_dao_ack_buf();

    rpl_dodag_t *my_dodag = rpl_get_joined_dodag(rpl_dao_ack_buf->rpl_instanceid);

    if (my_dodag == NULL) {
        return;
    }

    if (rpl_dao_ack_buf->rpl_instanceid != my_dodag->instance->id) {
        return;
    }

    if (rpl_dao_ack_buf->status != 0) {
        return;
    }

    dao_ack_received(my_dodag);

}

/* obligatory for each mode. normally not modified */
void rpl_send(ipv6_addr_t *destination, uint8_t *payload, uint16_t p_len, uint8_t next_header)
{
    uint8_t *p_ptr;
    ipv6_send_buf = get_rpl_send_ipv6_buf();
    p_ptr = get_rpl_send_payload_buf(ipv6_ext_hdr_len);

    ipv6_send_buf->version_trafficclass = IPV6_VER;
    ipv6_send_buf->trafficclass_flowlabel = 0;
    ipv6_send_buf->flowlabel = 0;
    ipv6_send_buf->nextheader = next_header;
    ipv6_send_buf->hoplimit = MULTIHOP_HOPLIMIT;
    ipv6_send_buf->length = HTONS(p_len);

    memcpy(&(ipv6_send_buf->destaddr), destination, 16);
    ipv6_net_if_get_best_src_addr(&(ipv6_send_buf->srcaddr), &(ipv6_send_buf->destaddr));

    icmp_send_buf = get_rpl_send_icmpv6_buf(ipv6_ext_hdr_len);
    icmp_send_buf->checksum = icmpv6_csum(ipv6_send_buf, icmp_send_buf);

    /* The packet was "assembled" in rpl_%mode%.c. Therefore rpl_send_buf was used.
     * Therefore memcpy is not needed because the payload is at the
     * right memory location already. */

    if (p_ptr != payload) {
        memcpy(p_ptr, payload, p_len);
    }

    ipv6_send_packet(ipv6_send_buf, NULL);
}
