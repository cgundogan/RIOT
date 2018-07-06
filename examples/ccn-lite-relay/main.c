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
#include "ccnl-pkt-builder.h"
#include "ccnl-producer.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pktdump.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (20480 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

#define BUF_SIZE (80)
static unsigned char _int_buf[BUF_SIZE];

int producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                   struct ccnl_pkt_s *pkt){
    (void)from;
    static const char *payload = "21.C";

    char s[CCNL_MAX_PREFIX_SIZE];

    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("generating content for: %s\n", s);
    struct ccnl_content_s *c = ccnl_mkContentObject(pkt->pfx, (unsigned char*)payload, strlen(payload), NULL);
    ccnl_content_add2cache(relay, c);

    return 0;
}

static int _enable_local_p(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    ccnl_set_local_producer(producer_func);

    return 0;
}

static int _consume(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    unsigned nums = atoi(argv[1]);
    unsigned delay = atoi(argv[2]);

    memset(_int_buf, '\0', BUF_SIZE);

    char name[40];
    for (unsigned i = 0; i < nums; i++) {
        int name_len = sprintf(name, "/ACM/ICN/Boston/18/Temp/%04d", i);
        name[name_len]='\0';
        printf("sending Interest: %s\n", name);
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL);
        ccnl_send_interest(prefix, _int_buf, BUF_SIZE, NULL);
        ccnl_prefix_free(prefix);
        xtimer_usleep(delay * 1000);
    }

    return 0;
}

static const shell_command_t shell_commands[] = {
    { "sp", "start producer", _enable_local_p },
    { "c", "start consumer", _consume },
    { NULL, NULL, NULL }
};

int main(void)
{
    tlsf_add_global_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Basic CCN-Lite example");

    ccnl_core_init();

    ccnl_start();

    /* get the default interface */
    gnrc_netif_t *netif;

    /* set the relay's PID, configure the interface to use CCN nettype */
    if (((netif = gnrc_netif_iter(NULL)) == NULL) ||
        (ccnl_open_netif(netif->pid, GNRC_NETTYPE_CCN) < 0)) {
        puts("Error registering at network interface!");
        return -1;
    }

#ifdef MODULE_NETIF
    gnrc_netreg_entry_t dump = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                          gnrc_pktdump_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &dump);
#endif

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
