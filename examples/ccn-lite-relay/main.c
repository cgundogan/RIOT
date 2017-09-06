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
#include "saul_reg.h"

#include "ccnl-pkt-builder.h"
#include "net/gnrc/netapi.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (10240 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

char hwaddr_str[2 * 3];

saul_reg_t *saul_temp, *saul_humid;

int generate_temp(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                  struct ccnl_pkt_s *pkt) {
    if (pkt && pkt->pfx && pkt->pfx->compcnt) {
        if (!memcmp(pkt->pfx->comp[0], hwaddr_str, pkt->pfx->complen[0])) {
            size_t len = 0;
            unsigned char *b = NULL;

            if (!memcmp(pkt->pfx->comp[1], "temp", pkt->pfx->complen[1])) {
                phydat_t r;
                saul_reg_read(saul_temp, &r);
                len = 5;
                char buffer[len];
                snprintf(buffer, len, "%d", r.val[0]);
                b = (unsigned char *)buffer;
            }
            else if (!memcmp(pkt->pfx->comp[1], "humid", pkt->pfx->complen[1])) {
                phydat_t r;
                saul_reg_read(saul_humid, &r);
                len = 5;
                char buffer[len];
                snprintf(buffer, len, "%d", r.val[0]);
                b = (unsigned char *)buffer;
            }

            if (b) {
                struct ccnl_content_s *c = ccnl_mkContentObject(pkt->pfx, b, len);

                c->last_used -= CCNL_CONTENT_TIMEOUT + 5;
                if (c) {
                    ccnl_content_add2cache(relay, c);
                }
                return 0;
            }
        }
    }
    return 1;
}

int main(void)
{
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Basic CCN-Lite example");

    ccnl_core_init();

    ccnl_start();

    /* get the default interface */
    kernel_pid_t ifs[GNRC_NETIF_NUMOF];

    ccnl_set_local_producer(generate_temp);

    saul_temp = saul_reg_find_nth(9);
    saul_humid = saul_reg_find_nth(10);

    /* set the relay's PID, configure the interface to use CCN nettype */
    if ((gnrc_netif_get(ifs) == 0) || (ccnl_open_netif(ifs[0], GNRC_NETTYPE_CCN) < 0)) {
        puts("Error registering at network interface!");
        return -1;
    }

    uint8_t hwaddr[2];
    int res = gnrc_netapi_get(ifs[0], NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
    gnrc_netif_addr_to_str(hwaddr_str, sizeof(hwaddr_str), hwaddr, res);

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
