/*
 * Copyright (C) 2013, 2014  INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     rpl
 * @{
 *
 * @file        rpl.h
 * @brief       RPL header. Declaration of global variables and functions needed for
 *              core functionality of RPL.
 *
 * Header which includes all core RPL-functions. Normally it shouldn't be necessary to
 * modify this file.
 *
 * @author      Eric Engel <eric.engel@fu-berlin.de>
 * @author      Fabian Brandt <fabianbr@zedat.fu-berlin.de>
 */

#ifndef __RPL_H
#define __RPL_H

#include <string.h>
#include <stdint.h>
#include <vtimer.h>
#include <transceiver.h>
#include "ipv6.h"
#include "rpl/rpl_dodag.h"
#include "rpl/rpl_of_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#undef CC1100_RADIO_MODE
#define CC1100_RADIO_MODE CC1100_MODE_WOR

#define RPL_PKT_RECV_BUF_SIZE 16
#define RPL_PROCESS_STACKSIZE KERNEL_CONF_STACKSIZE_MAIN

/* global variables */
extern kernel_pid_t rpl_process_pid;
extern uint8_t rpl_max_routing_entries;
extern msg_t rpl_msg_queue[RPL_PKT_RECV_BUF_SIZE];
extern char rpl_process_buf[RPL_PROCESS_STACKSIZE];
extern uint8_t rpl_buffer[BUFFER_SIZE - LL_HDR_LEN];

/**
 * @brief Initialization of RPL.
 *
 * This function initializes all basic RPL resources such as
 * corresponding objective functions and sixlowpan (including own address). Calls
 * initialization for mode as specified by PL_DEFAULT_MOP in rpl_structs.h.
 *
 * @param[in] if_id             ID of the interface, which correspond to the network under RPL-control
 *
 * @return 1 if initialization was successful
 * @return 0 if initialization was not successful
 *
 */
uint8_t rpl_init(int if_id);

/**
 * @brief Initialization of RPL-root.
 *
 * This function initializes all RPL resources to act as a root node with the specified instance id.
 * Because the root has different features in different modes, the core
 * initialization just calls the root-initialization of the chosen mode
 *
 * @param[in] instanceid               the id of the instance
 *
 */
void rpl_init_root(uint8_t instanceid);

/**
 * @brief Initialization of RPL-root in P2P-Mode
 *
 * This function initializes all RPL resources to act as a root node with the specified instance id
 * and the P2P-Mode MOP.
 * Because the root has different features in different modes, the core
 * initialization just calls the root-initialization of the chosen mode
 *
 * @param[in] instanceid        the id of the instance
 * @param[in] reply             if 1, the target MUST send a DRO
 * @param[in] hop_by_hop        1, if hop-by-hop route is desired, 0 for source routes
 * @param[in] no_of_routes      number of desired source routes, requires hop_by_hop = 0
 * @param[in] compr             number of prefix octets elided from the target field and the address vector
 * @param[in] lifetime          lifetime of the temporary dodag
 * @param[in] maxrank_nexthop   in DIO: upper limit for rank, in P2P-DRO: index of next hop in the address vector
 * @param[in] target            the target to find
 *
 */
void rpl_init_p2p(uint8_t instanceid, uint8_t reply, uint8_t hop_by_hop, uint8_t no_of_routes,
        uint8_t compr, uint8_t lifetime, uint8_t maxrank_nexthop, ipv6_addr_t target);

/**
 * @brief Sends a DIO-message to a given destination
 *
 * This function sends a DIO message to a given destination. Because nodes can act
 * differently in different modes, this function calls the DIO
 * sending function of the chosen mode.
 *
 * @param[in] destination       IPv6-address of the destination of the DIO. Should be a direct neighbor.
 * @param[in] dodag             the appropriate DODAG
 *
 */
void rpl_send_DIO(ipv6_addr_t *destination, rpl_dodag_t *dodag);

/**
 * @brief Sends a DAO-message to a given destination
 *
 * This function sends a DAO message to a given destination. Because nodes can act
 * differently in different modes, this function calls the DAO
 * sending function of the chosen mode.
 *
 * @param[in] destination       IPv6-address of the destination of the DAO. Should be the preferred parent.
 * @param[in] lifetime          Lifetime of the node. Reflect the estimated time of presence in the network.
 * @param[in] default_lifetime  If true, param lifetime is ignored and lifetime is dodag default-lifetime
 * @param[in] start_index       Describes whether a DAO must be split because of too many routing entries.
 * @param[in] dodag             the appropriate DODAG
 *
 */
void rpl_send_DAO(ipv6_addr_t *destination, uint8_t lifetime, bool default_lifetime, uint8_t start_index, rpl_dodag_t *dodag);

/**
 * @brief Sends a DIS-message to a given destination
 *
 * This function sends a DIS message to a given destination or multicast-address. Because nodes can act
 * differently in different modes, this function calls the DIS
 * sending function of the chosen mode.
 *
 * @param[in] destination       IPv6-address of the destination of the DIS. Should be a direct neighbor or multicast-address.
 *
 */
void rpl_send_DIS(ipv6_addr_t *destination);

/**
 * @brief Sends a DAO acknowledgment-message to a given destination
 *
 * This function sends a DAO_ACK message to a given destination. Because nodes can act
 * differently in different modes, this function calls the DAO_ACK
 * sending function of the chosen mode.
 *
 * @param[in] destination       IPv6-address of the destination of the DAO_ACK. Should be a direct neighbor.
 * @param[in] dodag             the appropriate DODAG
 *
 */
void rpl_send_DAO_ACK(ipv6_addr_t *destination, rpl_dodag_t *dodag);

/**
 * @brief Sends a DRO-message
 *
 * This function sends a DRO message containing a RDO option to the multicast address
 *
 * @param[in] dodag       the appropriate DODAG
 *
 */
void rpl_send_DRO(rpl_dodag_t *dodag);

/**
 * @brief Receives a DIO message
 *
 * This function handles receiving a DIO message. Because nodes can act differently in different modes,
 * this function just calls the receiving function of the chosen mode.
 *
 */
void rpl_recv_DIO(void);

/**
 * @brief Receives a DAO message
 *
 * This function handles receiving a DAO message. Because nodes can act differently in different modes,
 * this function just calls the receiving function of the chosen mode.
 *
 */
void rpl_recv_DAO(void);

/**
 * @brief Receives a DIS message
 *
 * This function handles receiving a DIS message. Because nodes can act differently in different modes,
 * this function just calls the receiving function of the chosen mode.
 *
 */
void rpl_recv_DIS(void);

/**
 * @brief Receives a DAO acknowledgment message
 *
 * This function handles receiving a DAO_ACK message. Because nodes can act differently in different modes,
 * this function just calls the receiving function of the chosen mode.
 *
 */
void rpl_recv_DAO_ACK(void);

/**
 * @brief Initialization of RPl-root.
 *
 * This function initializes all RPL resources especially for root purposes.
 * corresponding objective functions and sixlowpan (including own address).
 * @param arg ignored
 * @returns nothing
 */
void *rpl_process(void *arg);

/**
 * @brief Returns next hop from routing table.
 *
 * @deprecated This function is obsolete and will be removed shortly. This will be replaced with a
 * common routing information base.
 *
 * @param[in] addr                  Destination address
 *
 * @return Next hop address
 *
 * */
ipv6_addr_t *rpl_get_next_hop(ipv6_addr_t *addr);

/**
 * @brief Adds routing entry to routing table
 *
 * @deprecated This function is obsolete and will be removed shortly. This will be replaced with a
 * common routing information base.
 *
 * @param[in] addr                  Destination address
 * @param[in] next_hop              Next hop address
 * @param[in] lifetime              Lifetime of the entry
 * @param[in] dodag                 the appropriate DODAG
 *
 * */
void rpl_add_routing_entry(ipv6_addr_t *addr, ipv6_addr_t *next_hop, uint16_t lifetime, rpl_dodag_t *dodag);

/**
 * @brief Deletes routing entry to routing table
 *
 * @deprecated This function is obsolete and will be removed shortly. This will be replaced with a
 * common routing information base.
 *
 * @param[in] addr                  Destination address
 *
 * */
void rpl_del_routing_entry(ipv6_addr_t *addr);

/**
 * @brief Finds routing entry for a given destination.
 *
 * @deprecated This function is obsolete and will be removed shortly. This will be replaced with a
 * common routing information base.
 *
 * @param[in] addr                  Destination address
 * @param[in] dodag                 the appropriate DODAG
 *
 * @return Routing entry address
 *
 * */
rpl_routing_entry_t *rpl_find_routing_entry(ipv6_addr_t *addr, rpl_dodag_t *dodag);

/**
 * @brief Clears routing table.
 *
 * @deprecated This function is obsolete and will be removed shortly. This will be replaced with a
 * common routing information base.
 *
 * */
void rpl_clear_routing_table(void);

/**
 * @brief Returns routing table
 *
 * @deprecated This function is obsolete and will be removed shortly. This will be replaced with a
 * common routing information base.
 *
 * @return Routing table
 *
 * */
rpl_routing_entry_t *rpl_get_routing_table(void);

/**
 * @brief Returns the network status of the actual node
 *
 * @return 1 if root, 0 otherwise
 *
 * */
uint8_t rpl_is_root(void);

#if RPL_DEFAULT_MOP == RPL_NON_STORING_MODE

/**
 * @brief Adds one pair of child and its parent to the source routing table
 *
 * @deprecated This function is obsolete and will be removed shortly. This will be replaced with a
 * common routing information base.
 *
 * @param[in] child                  Child IPv6-address
 * @param[in] parent                 Parent IPv6-address
 * @param[in] lifetime               Lifetime of the relation
 *
 * */
void rpl_add_srh_entry(ipv6_addr_t *child, ipv6_addr_t *parent, uint16_t lifetime);

/**
 * @brief Constructs a source routing header based on an original IPv6-header
 *
 * @param[in] act_ipv6_hdr                  Pointer to original IPv6-packet header
 * @return Source routing header or NULL
 *
 * */
ipv6_srh_t *rpl_get_srh_header(ipv6_hdr_t *act_ipv6_hdr);

/**
 * @brief Manages sending an SRH-header integrated in an original IPv6-package to the next hop.
 *
 * @param[in] buf                  Pointer to original payload
 * @param[in] len                  Length of the original payload
 * @param[in] src                  Original source address
 * @param[in] dest                 Destination address
 * @param[in] srh_header           Pre-build source routing header
 * @param[in] srh_length           Length of the pre-built source routing header
 * @return                         Status of sending progress
 * */
int rpl_srh_sendto(const void *buf, uint16_t len, ipv6_addr_t *src, ipv6_addr_t *dest, ipv6_srh_t *srh_header, uint8_t srh_length);

/**
 * @brief Sends IPC-message to the service, which is indicated by the next-header-field in the source routing header
 *
 * @param[in] ipv6_header          Actual IPv6-header
 * @return IPv6-address of the next-hop. Is NULL on error occurrence.
 *
 * */
void rpl_remove_srh_header(ipv6_hdr_t *ipv6_header, const void *buf, uint8_t nextheader);

#endif /* RPL_DEFAULT_MOP == RPL_NON_STORING_MODE */

#ifdef __cplusplus
}
#endif
/** @} */
#endif /* __RPL_H */
