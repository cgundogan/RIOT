/*
 * Copyright (C) 2013  INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup rpl
 * @{
 * @file    rpl_structs.h
 * @brief   RPL data structs
 *
 * File, which defines all structs used by RPL.
 *
 * @author  Eric Engel <eric.engel@fu-berlin.de>
 * @}
 */

#ifndef RPL_STRUCTS_H_INCLUDED
#define RPL_STRUCTS_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include "ipv6.h"
#include "trickle.h"
#include "rpl_config.h"

/* Modes of Operation */

/* DIO Base Object (RFC 6550 Fig. 14) */
struct __attribute__((packed)) rpl_dio_t {
    uint8_t rpl_instanceid;
    uint8_t version_number;
    uint16_t rank;
    uint8_t g_mop_prf;
    uint8_t dtsn;
    uint8_t flags;
    uint8_t reserved;
    ipv6_addr_t dodagid;
};

struct __attribute__((packed)) rpl_dis_t {
    uint8_t flags;
    uint8_t reserved;
};

/* DAO Base Object (RFC 6550 Fig. 16) */
struct __attribute__((packed)) rpl_dao_t {
    uint8_t rpl_instanceid;
    uint8_t k_d_flags;
    uint8_t reserved;
    uint8_t dao_sequence;
};

/* DAO ACK Base Object (RFC 6550 Fig. 17.) */
struct __attribute__((packed)) rpl_dao_ack_t {
    uint8_t rpl_instanceid;
    uint8_t d_reserved;
    uint8_t dao_sequence;
    uint8_t status;
};

/* DODAG ID Struct */
/* may be present in dao or dao_ack packets */
struct __attribute__((packed)) dodag_id_t {
    ipv6_addr_t dodagid;
};

/* RPL-Option Generic Format (RFC 6550 Fig. 19) */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t length;
} rpl_opt_t;

/* DODAG Configuration-Option (RFC 6550 Fig. 24) */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t length;
    uint8_t flags_a_pcs;
    uint8_t DIOIntDoubl;
    uint8_t DIOIntMin;
    uint8_t DIORedun;
    uint16_t MaxRankIncrease;
    uint16_t MinHopRankIncrease;
    uint16_t ocp;
    uint8_t reserved;
    uint8_t default_lifetime;
    uint16_t lifetime_unit;
} rpl_opt_dodag_conf_t;

/* RPL Solicited Information Option (RFC 6550 Fig. 28) */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t length;
    uint8_t rplinstanceid;
    uint8_t VID_Flags;
    ipv6_addr_t dodagid;
    uint8_t version;
} rpl_opt_solicited_t;

/* RPL Target-Option (RFC 6550 Fig. 25) */
/* TODO: ipv6_addr_t target may be replaced by a target prefix of variable length */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t length;
    uint8_t flags;
    uint8_t prefix_length;
    ipv6_addr_t target;
} rpl_opt_target_t;

/* RPL Transit-Option (RFC 6550 Fig. 26) */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t length;
    uint8_t e_flags;
    uint8_t path_control;
    uint8_t path_sequence;
    uint8_t path_lifetime;
    ipv6_addr_t parent;
} rpl_opt_transit_t;

struct rpl_dodag_t;

typedef struct {
    ipv6_addr_t         addr;
    uint16_t            rank;
    uint8_t             dtsn;
    struct rpl_dodag_t *dodag;
    uint16_t            lifetime;
    double              link_metric;
    uint8_t             link_metric_type;
    uint8_t             used;
} rpl_parent_t;

struct rpl_of_t;

typedef struct {
    uint8_t id;
    uint8_t used;
    uint8_t joined;
} rpl_instance_t;

//Node-internal representation of a DODAG, with nodespecific information
typedef struct rpl_dodag_t {
    rpl_instance_t *instance;
    ipv6_addr_t dodag_id;
    uint8_t used;
    uint8_t mop;
    uint8_t dtsn;
    uint8_t prf;
    uint8_t dio_interval_doubling;
    uint8_t dio_min;
    uint8_t dio_redundancy;
    uint16_t maxrankincrease;
    uint16_t minhoprankincrease;
    uint8_t default_lifetime;
    uint16_t lifetime_unit;
    uint8_t version;
    uint8_t grounded;
    uint16_t my_rank;
    uint8_t node_status;
    uint8_t dao_seq;
    uint16_t min_rank;
    uint8_t joined;
    uint8_t i_am_root;
    uint8_t is_p2p;
    rpl_parent_t *my_preferred_parent;
    struct rpl_of_t *of;
    trickle_t trickle;
    bool ack_received;
    uint8_t dao_counter;
    timex_t dao_time;
    vtimer_t dao_timer;
    uint8_t p2p_compr;
    uint8_t p2p_no_of_routes;
    uint8_t p2p_hop_by_hop;
    uint8_t p2p_reply;
    uint8_t p2p_lifetime;
    int8_t p2p_lifetime_sec;
    uint8_t p2p_maxrank_nexthop;
    ipv6_addr_t p2p_target;
    ipv6_addr_t p2p_addresses[RPL_P2P_RDO_MAX_ADDRESSES];
} rpl_dodag_t;

typedef struct rpl_of_t {
    uint16_t ocp;
    uint16_t (*calc_rank)(rpl_parent_t *parent, uint16_t base_rank);
    rpl_parent_t *(*which_parent)(rpl_parent_t *, rpl_parent_t *);
    rpl_dodag_t *(*which_dodag)(rpl_dodag_t *, rpl_dodag_t *);
    void (*reset)(rpl_dodag_t *);
    void (*parent_state_callback)(rpl_parent_t *, int, int);
    void (*init)(void);  //OF specific init function
    void (*process_dio)(void);  //DIO processing callback (acc. to OF0 spec, chpt 5)
} rpl_of_t;

typedef struct {
    ipv6_addr_t address;
    ipv6_addr_t next_hop;
    uint16_t lifetime;
    uint8_t used;
    rpl_dodag_t *dodag;
} rpl_routing_entry_t;

#define RPL_P2P_GET(y, name)        ( ( (y) & RPL_P2P_##name##_MASK ) >> RPL_P2P_##name##_SHIFT )
#define RPL_P2P_SET(y, x, name)     ( y = ( (y) & ~RPL_P2P_##name##_MASK ) | \
                                    ( ((x) << RPL_P2P_##name##_SHIFT) & RPL_P2P_##name##_MASK ) )
/* P2P Route Discovery Option (P2P-RDO) (RFC 6997 Fig. 1, Page 15) */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t length;
    uint8_t compr           :4;
    uint8_t no_of_routes    :1;
    uint8_t hop_by_hop      :2;
    uint8_t reply           :1;
    uint8_t lifetime        :2;
    uint8_t maxrank_nexthop :6;
    ipv6_addr_t target;
} rpl_opt_p2p_rdo_t;

/* P2P Discovery Reply Object (P2P-DRO) (RFC 6997 Fig. 2, Page 19) */
typedef struct __attribute__((packed)) {
#define RPL_P2P_RDO_STOP_MASK       (0x0001)
#define RPL_P2P_RDO_STOP_SHIFT      (0x0)
#define RPL_P2P_RDO_ACK_MASK        (0x0002)
#define RPL_P2P_RDO_ACK_SHIFT       (0x1)
#define RPL_P2P_RDO_SEQ_NO_MASK     (0x000C)
#define RPL_P2P_RDO_SEQ_NO_SHIFT    (0x2)
#define RPL_P2P_RDO_RESERVED_MASK   (0xFFF0)
#define RPL_P2P_RDO_RESERVED_SHIFT  (0x4)
    uint8_t instance_id;
    uint8_t version;
    uint16_t flags_reserved;
    ipv6_addr_t dodagid;
} rpl_p2p_dro_t;

#ifdef __cplusplus
}
#endif

#endif
