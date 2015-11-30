/*
 * Copyright (C) 2015 Kaspar Schleiser <kaspar@schleiser.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 */

/**
 * @ingroup auto_init_gnrc_netif
 * @{
 *
 * @file
 * @brief   Auto initialization for ethernet-over-serial module
 *
 * @author  Kaspar Schleiser <kaspar@schleiser.de>
 */

#ifdef MODULE_ETHOS

#define ENABLE_DEBUG (0)
#include "debug.h"

#include "eth_over_serial.h"
#include "periph/uart.h"
#include "net/gnrc/netdev2/eth.h"

eth_over_serial_t eth_over_serial;

/**
 * @brief   Define stack parameters for the MAC layer thread
 * @{
 */
#define MAC_STACKSIZE           (THREAD_STACKSIZE_DEFAULT + DEBUG_EXTRA_STACKSIZE)
#define MAC_PRIO                (THREAD_PRIORITY_MAIN - 4)

/**
 * @brief   Stacks for the MAC layer threads
 */
static char _netdev2_eth_stack[MAC_STACKSIZE];
static gnrc_netdev2_t _gnrc_eth_over_serial;

static uint8_t _inbuf[2048];

void auto_init_eth_over_serial(void)
{
    DEBUG("auto_init_eth_over_serial(): initializing device...\n");

    /* setup netdev2 device */
    eth_over_serial_setup(&eth_over_serial, ETHOS_UART,
            ETHOS_BAUDRATE, _inbuf, sizeof(_inbuf));

    /* initialize netdev2<->gnrc adapter state */
    gnrc_netdev2_eth_init(&_gnrc_eth_over_serial, (netdev2_t*)&eth_over_serial);

    /* start gnrc netdev2 thread */
    gnrc_netdev2_init(_netdev2_eth_stack, MAC_STACKSIZE,
            MAC_PRIO, "gnrc_eth_over_serial", &_gnrc_eth_over_serial);
}

#else
typedef int dont_be_pedantic;
#endif /* MODULE_ETHOS */
/** @} */
