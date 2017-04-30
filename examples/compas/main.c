/*
 * Copyright (C) 2015 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Basic ccn-lite relay example (produce and consumer via shell)
 *
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */

#include <stdio.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "ccn-lite-riot.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netapi.h"

#include "luid.h"
#include "random.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (20480 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

kernel_pid_t ccnl_pid;

#define MAX_ADDR_LEN            (8U)

int main(void)
{
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    ccnl_core_init();

    ccnl_pid = ccnl_start();

    /* get the default interface */
    kernel_pid_t ifs[GNRC_NETIF_NUMOF];

    /* set the relay's PID, configure the interface to use CCN nettype */
    if ((gnrc_netif_get(ifs) == 0) || (ccnl_open_netif(ifs[0], GNRC_NETTYPE_CCN) < 0)) {
        return -1;
    }

    uint32_t seed;
    luid_get(&seed, sizeof(seed));
    random_init(seed);

    uint16_t src_len = 8;
    gnrc_netapi_set(ifs[0], NETOPT_SRC_LEN, 0, (uint16_t *)&src_len, sizeof(uint16_t));

    uint8_t hwaddr[MAX_ADDR_LEN];
    int res = gnrc_netapi_get(ifs[0], NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
    char hwaddr_str[res * 3];
    printf("seed:%u;hwaddr=%s\n", (unsigned) seed, gnrc_netif_addr_to_str(hwaddr_str, sizeof(hwaddr_str), hwaddr, res));

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
