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
#include "net/gnrc/pktdump.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netapi.h"

#include "ccnl-pkt-builder.h"
#include "ccnl-producer.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (10240 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

static unsigned len = 0;

int producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                   struct ccnl_pkt_s *pkt)
{
	if (from->ifndx == -1) {
		return 0;
	}
	static unsigned char buffer[CCNL_MAX_PACKET_SIZE];
	memset(buffer, 'A', len);
	struct ccnl_content_s *c = ccnl_mkContentObject(pkt->pfx, buffer, len);
	ccnl_content_add2cache(relay, c);
    return 0;
}

int set_len(int argc, char **argv)
{
    (void) argc;
    len = atoi(argv[1]);
    printf("LEN: %u\n", len);
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "len", "set data len", set_len },
    { NULL, NULL, NULL }
};

int main(void)
{
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Basic CCN-Lite example");

    ccnl_core_init();

    ccnl_start();

	ccnl_set_local_producer(producer_func);

    /* get the default interface */
    gnrc_netif_t *netif;

    /* set the relay's PID, configure the interface to use CCN nettype */
    if (((netif = gnrc_netif_iter(NULL)) == NULL) ||
        (ccnl_open_netif(netif->pid, GNRC_NETTYPE_CCN) < 0)) {
        puts("Error registering at network interface!");
        return -1;
    }
    uint16_t chan = 26;
    netif = gnrc_netif_iter(NULL);
    gnrc_netapi_set(netif->pid, NETOPT_CHANNEL, 0, &chan, sizeof(chan));

#ifdef MODULE_NETIF
    gnrc_netreg_entry_t dump = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                          gnrc_pktdump_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &dump);
#endif

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
