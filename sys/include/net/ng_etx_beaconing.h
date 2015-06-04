/*
 * Copyright 2014 Freie Universität Berlin
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ng_etx_beaconing ETX daemon
 * @ingroup     net
 * @brief       ETX daemon based on link-layer frames
 * @{
 * @file
 *
 * Header-file, which includes all constants and functions used for ETX-based beaconing.
 *
 * @author  Stephan Arndt <arndtste@zedat.fu-berlin.de>
 * @author  Cenk Gündoğan <cnkgndgn@gmail.com>
 * @}
 */

#ifndef ETX_BEACONING_H_
#define ETX_BEACONING_H_
#include <stdint.h>
#include "net/ng_netbase.h"
#include "net/ng_ipv6/nc.h"
#include "net/ng_netif/hdr.h"
#include "thread.h"
#include "kernel_types.h"
#include "net/ng_nettype.h"
#include "vtimer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Default stack size to use for the etx beaconing thread
 */
#ifndef NG_ETX_BEACONING_STACK_SIZE
#define NG_ETX_BEACONING_STACK_SIZE (THREAD_STACKSIZE_DEFAULT)
#endif

/**
 * @brief   Default priority for the etx beaconing thread
 */
#ifndef NG_ETX_BEACONING_PRIO
#define NG_ETX_BEACONING_PRIO            (THREAD_PRIORITY_MAIN - 3)
#endif

/**
 * @brief   Default message queue size to use for the etx beaconing thread.
 */
#ifndef NG_ETX_BEACONING_MSG_QUEUE_SIZE
#define NG_ETX_BEACONING_MSG_QUEUE_SIZE  (8U)
#endif

/**
 * @brief Number of max neighbors
 */
#ifndef NG_ETX_BEACONING_NEIGHBORS_NUMOF
#define NG_ETX_BEACONING_NEIGHBORS_NUMOF    (3U)
#endif

/**
 * @brief Message type denoting the beaconing process
 */
#ifndef NG_ETX_BEACONING_MSG_TYPE_BEACON
#define NG_ETX_BEACONING_MSG_TYPE_BEACON    (0x9876)
#endif

/**
 * @brief Interval of the beaconing in seconds
 */
#ifndef NG_ETX_BEACONING_INTERVAL
#define NG_ETX_BEACONING_INTERVAL    (2U)
#endif

/**
 * @brief Number of transmissions before calculating the ETX value
 */
#ifndef NG_ETX_BEACONING_TRANSMISSIONS
#define NG_ETX_BEACONING_TRANSMISSIONS    (10U)
#endif

/**
 * @brief Penalty to apply when the current ETX value cannot be calculated
 */
#ifndef NG_ETX_BEACONING_PENALTY
#define NG_ETX_BEACONING_PENALTY    (5U)
#endif

/**
 * @brief Moving average window used to smooth out ETX values
 */
#ifndef NG_ETX_BEACONING_WINDOW
#define NG_ETX_BEACONING_WINDOW    (4U)
#endif

/**
 * @brief   Container to save neighbors and their ETX values
 */
typedef struct {
    bool used;
    uint8_t l2_addr[NG_NETIF_HDR_L2ADDR_MAX_LEN];   /**< Link layer address of the neighbor */
    uint8_t l2_addr_len;                            /**< length of the link layer address */
    double etx_window[NG_ETX_BEACONING_WINDOW];     /**< etx values for the moving average */
    uint8_t current_window;                         /**< current position in the etx window */
    double etx;                 /**< etx value of the neighbor */
    uint16_t round;             /**< num of expected frames sent to/from the neighbor */
    uint16_t sent;              /**< num of frames arrived at the neighbor */
    uint16_t recvd;             /**< num of frames arrived from the neighbor */
    bool recvd_in_round;        /**< indicator if a frame was received in this round */
} ng_etx_container_t;

extern ng_etx_container_t ng_etx_neighbors[NG_ETX_BEACONING_NEIGHBORS_NUMOF];

kernel_pid_t ng_etx_beaconing_init(kernel_pid_t if_pid);

#ifdef __cplusplus
}
#endif

#endif /* ETX_BEACONING_H_ */
