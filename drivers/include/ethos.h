/*
 * Copyright (C) 2015 Kaspar Schleiser <kaspar@schleiser.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @defgroup    drivers_ethos ethos
 * @ingroup     drivers_netdev
 * @brief       Driver for the ethernet-over-serial module
 * @{
 *
 * @file
 * @brief       Interface definition for the ethernet-over-serial module
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 */

#ifndef ETHOS_H
#define ETHOS_H

#include "kernel_types.h"
#include "periph/uart.h"
#include "net/netdev2.h"
#include "tsrb.h"
#include "mutex.h"

#ifdef __cplusplus
extern "C" {
#endif

/* if using ethos + stdio, use STDIO values unless overridden */
#ifdef USE_ETHOS_FOR_STDIO
#include "board.h"
#ifndef ETHOS_UART
#define ETHOS_UART  STDIO
#endif
#ifndef ETHOS_BAUDRATE
#define ETHOS_BAUDRATE STDIO_BAUDRATE
#endif
#endif

/**
 * @brief Escape char definitions
 * @{
 */
#define ETHOS_FRAME_DELIMITER   (0x7E)
#define ETHOS_ESC_CHAR          (0x7D)
#define ETHOS_FRAME_TYPE_TEXT   (0x1)
/** @} */

/**
 * @brief   enum describing line state
 */
typedef enum {
    WAIT_FRAMESTART,
    IN_FRAME,
    IN_ESCAPE
} line_state_t;

/**
 * @brief ethos netdev2 device
 * @extends netdev2_t
 */
typedef struct {
    netdev2_t netdev;       /**< extended netdev2 structure */
    uart_t uart;            /**< UART device the to use */
    uint8_t mac_addr[6];    /**< this device's MAC address */
    tsrb_t inbuf;           /**< ringbuffer for incoming data */
    line_state_t state;     /**< Line status variable */
    size_t framesize;       /**< size of currently incoming frame */
    unsigned frametype;     /**< type of currently incoming frame */
    size_t last_framesize;  /**< size of last completed frame */
    mutex_t out_mutex;      /**< mutex used for locking concurrent sends */
} ethos_t;

/**
 * @brief Setup an ethos based device state.
 *
 * @param[out]  dev         handle of the device to initialize
 * @param[in]   uart        UART device to use
 * @param[in]   baudrate    baudrate for UART device
 */
void ethos_setup(ethos_t *dev, uart_t uart, uint32_t baudrate, uint8_t *buf, size_t bufsize);

void ethos_send_frame(ethos_t *dev, const uint8_t *data, size_t len, unsigned frame_type);

#ifdef __cplusplus
}
#endif
#endif /* ETHOS_H */
/** @} */
