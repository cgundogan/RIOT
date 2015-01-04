/*
 * Copyright (C) 2014 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net
 * @brief       Routing Protocol for Low power and Lossy Networks
 * @{
 *
 * @file
 * @brief       RPL storing-mode header
 *
 * Header which includes all mode related RPL-functions. All functions are mandatory for any
 * RPL-mode. Describes receiving and sending of all RPL-related messages and special initialization behavior.
 *
 * @author      Eric Engel <eric.engel@fu-berlin.de>
 * @author      Fabian Brandt <fabianbr@zedat.fu-berlin.de>
 */

#ifndef __RPL_SM_H
#define __RPL_SM_H

#include "rpl_structs.h"
#include "rpl_config.h"
#include "rpl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialization of RPL-root.
 *
 * This function initializes all RPL resources especially for root purposes. Initializes a new DODAG and sets
 * itself as root. Starts trickle-timer so sending DIOs starts and other can join the DODAG.
 *
 * @param[in] instanceid       the id of the instance
 *
 */
void rpl_init_root_mode(uint8_t instanceid);

/**
 * @brief Initialization of RPL-root in P2P-Mode
 *
 * This function initializes all RPL resources especially for root purposes with the P2P-Mode MOP.
 * Initializes a new DODAG and sets itself as root. Starts trickle-timer so sending DIOs starts and other can join the DODAG.
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
void rpl_init_p2p_mode(uint8_t instanceid, uint8_t reply, uint8_t hop_by_hop, uint8_t no_of_routes,
        uint8_t compr, uint8_t lifetime, uint8_t maxrank_nexthop, ipv6_addr_t target);

/**
 * @brief Initialization of RPL storing mode.
 *
 * This function initializes all basic RPL mode resources. For this mode this includes only acquiring the own
 * address.
 *
 * @param[in] my_ipv6_address       Own IPv6 address as assigned by RPL core-initialization.
 *
 */
void rpl_init_mode(ipv6_addr_t *my_ipv6_address);

/**
 * @brief Sends a DIO-message to a given destination
 *
 * This function sends a DIO message to a given destination. This is triggered by the trickle-timer.
 *
 * @param[in] destination           IPv6-address of the destination of the DIO. Should be a direct neighbor or multicast address.
 * @param[in] dodag                 the approriate DODAG
 *
 */
void rpl_send_DIO_mode(ipv6_addr_t *destination, rpl_dodag_t *dodag);

/**
 * @brief Returns whether a node is root or not
 *
 * This function initializes all basic RPL mode resources. For this mode this includes only acquiring the own
 * address.
 *
 * @return 1 if node is root
 * @return 0 if node is not root
 *
 */
uint8_t rpl_is_root_mode(void);

/**
 * @brief Sends a DAO-message to a given destination
 *
 * This function sends a DAO message to a given destination.
 *
 * @param[in] destination           IPv6-address of the destination of the DAO. Should be the proffered parent.
 * @param[in] lifetime              Lifetime of the node. Reflect the estimated time of presence in the network.
 * @param[in] default_lifetime      If true, param lifetime is ignored and lifetime is DODAG default-lifetime
 * @param[in] start_index           Describes whether a DAO must be split because of too many routing entries.
 * @param[in] dodag                 the appropriate DODAG
 *
 */
void rpl_send_DAO_mode(ipv6_addr_t *destination, uint8_t lifetime, bool default_lifetime, uint8_t start_index, rpl_dodag_t *dodag);

/**
 * @brief Sends a DIS-message to a given destination
 *
 * This function sends a DIS message to a given destination.
 *
 * @param[in] destination           IPv6-address of the destination of the DIS. Should be a direct neighbor.
 *
 */
void rpl_send_DIS_mode(ipv6_addr_t *destination);

/**
 * @brief Sends a DAO acknowledgment-message to a given destination
 *
 * This function sends a DAO_ACK message to a given destination.
 *
 * @param[in] destination           IPv6-address of the destination of the DAO_ACK. Should be a direct neighbor.
 * @param[in] dodag                 the appropriate DODAG
 *
 */
void rpl_send_DAO_ACK_mode(ipv6_addr_t *destination, rpl_dodag_t *dodag);

/**
 * @brief Sends a DRO-message containing a RDO option to the multicast address
 *
 * @param[in] dodag           the appropriate DODAG
 *
 */
void rpl_send_DRO_mode(rpl_dodag_t *dodag);

/**
 * @brief Receives a DIO message
 *
 * This function handles receiving a DIO message in any mode .
 *
 */
void rpl_recv_DIO_mode(void);

/**
 * @brief Receives a DAO message
 *
 * This function handles receiving a DAO message in any mode.
 *
 */
void rpl_recv_DAO_mode(void);

/**
 * @brief Receives a DIS message
 *
 * This function handles receiving a DIS message in any mode.
 *
 */
void rpl_recv_DIS_mode(void);

/**
 * @brief Receives a DAO acknowledgment message
 *
 * This function handles receiving a DAO_ACK message in any mode.
 *
 */
void rpl_recv_dao_ack_mode(void);

/**
 * @brief Receives a DRO
 */
void rpl_recv_DRO_mode(void);

/**
 * @brief Sends a RPL message to a given destination
 *
 * This function sends any RPl related messages to a given destination. This implementation should be equal
 * for all modes and therefore should not be altered. Every mode related RPL-sending function calls this for
 * relaying it in lower layers to sixlowpan.
 *
 * @param[in] destination           IPv6-address of the destination of the message.
 * @param[in] payload               Payload of the message.
 * @param[in] p_len                 Length of the message
 * @param[in] next_header           Index to next header in message.
 *
 */
void rpl_send(ipv6_addr_t *destination, uint8_t *payload, uint16_t p_len, uint8_t next_header);

#ifdef __cplusplus
}
#endif

#endif /* __RPL_SM_H */
/** @} */
