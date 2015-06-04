/*
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_shell_commands
 * @{
 *
 * @file
 * @brief       Shell commands for interacting with the ETX daemon
 *
 * @author      Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/ng_etx_beaconing.h"

static char addr_str[NG_NETIF_HDR_L2ADDR_MAX_LEN * 3];

int _etx(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    puts("neighbors:");
    for (uint8_t i = 0; i < NG_ETX_BEACONING_NEIGHBORS_NUMOF; i++) {
        if (ng_etx_neighbors[i].used) {
            printf("\t[%s | ETX: %f | r: %d | sent: %d | recvd: %d]\n",
                 ng_netif_addr_to_str((char *) addr_str, sizeof(addr_str),
                     ng_etx_neighbors[i].l2_addr, ng_etx_neighbors[i].l2_addr_len),
                 ng_etx_neighbors[i].etx, ng_etx_neighbors[i].round, ng_etx_neighbors[i].sent,
                 ng_etx_neighbors[i].recvd);
        }
    }
    return 0;
}
