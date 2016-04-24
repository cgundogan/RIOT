/*
 * Copyright (C) 2016 INRIA
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_netstats Packet statistics per module
 * @ingroup     net
 * @brief       Each module may store information about sent and received packets
 * @{
 *
 * @file
 * @brief       Definition of net statistics
 *
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 */

#include <stdint.h>

#ifndef NETSTATS_H
#define NETSTATS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name @ref net_netstats module names
 * @{
 */
#define NETSTATS_LAYER2     (0x01)
#define NETSTATS_IPV6       (0x02)
#define NETSTATS_RPL        (0x03)
#define NETSTATS_ALL        (0xFF)
/** @} */

/**
 * @brief       Global statistics struct
 */
typedef struct {
    uint32_t tx_unicast_count;  /**< packets sent via unicast */
    uint32_t tx_mcast_count;    /**< packets sent via multicast
                                     (including broadcast) */
    uint32_t tx_success;        /**< successful sending operations
                                     (either acknowledged or unconfirmed
                                     sending operation, e.g. multicast) */
    uint32_t tx_failed;         /**< failed sending operations */
    uint32_t tx_bytes;          /**< sent bytes */
    uint32_t rx_count;          /**< received (data) packets */
    uint32_t rx_bytes;          /**< received bytes */
} netstats_t;

/**
 * @brief       Global statistics struct for RPL control messages
 */
typedef struct {
    uint32_t dio_rx_count;      /**< DIOs received */
    uint32_t dio_tx_count;      /**< DIOs sent */
#ifdef MODULE_GNRC_RPL_BLOOM
    uint32_t dio_bl_rx_count;   /**< DIOs received */
    uint32_t dio_bl_rx_bytes;   /**< received bytes of DIOs */
#endif
    uint32_t dis_rx_count;      /**< DISs received */
    uint32_t dis_tx_count;      /**< DISs sent */
    uint32_t dao_rx_count;      /**< DAOs received */
    uint32_t dao_tx_count;      /**< DAOs sent */
    uint32_t dao_ack_rx_count;  /**< DAO-ACKs received */
    uint32_t dao_ack_tx_count;  /**< DAO-ACKs sent */
    uint32_t dio_rx_bytes;      /**< received bytes of DIOs */
    uint32_t dio_tx_bytes;      /**< sent bytes of DIOs */
    uint32_t dis_rx_bytes;      /**< received bytes of DISs */
    uint32_t dis_tx_bytes;      /**< sent bytes of DISs */
    uint32_t dao_rx_bytes;      /**< received bytes of DAOs */
    uint32_t dao_tx_bytes;      /**< sent bytes of DAOs */
    uint32_t dao_ack_rx_bytes;  /**< received bytes of DAO-ACKs */
    uint32_t dao_ack_tx_bytes;  /**< sent bytes of DAO-ACKs */
} netstats_rpl_t;

#ifdef __cplusplus
}
#endif

#endif /* NETSTATS_H */
/** @} */
