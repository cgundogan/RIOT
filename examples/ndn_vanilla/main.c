/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */


#include <stdio.h>

#ifdef MODULE_TLSF
#include "tlsf-malloc.h"
#endif
#include "msg.h"
#include "shell.h"
#include "ccn-lite-riot.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pktdump.h"
#include "pktcnt.h"
#include "xtimer.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#ifdef MODULE_TLSF
/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (20240 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];
#endif


#ifndef NUM_REQUESTS
#define NUM_REQUESTS            (5u)
#endif

#ifndef DELAY_REQUEST
#define DELAY_REQUEST           (1000000u) // us
#endif

#ifndef CONSUMER_THREAD_PRIORITY
#define CONSUMER_THREAD_PRIORITY (THREAD_PRIORITY_MAIN - 1)
#endif

static char _consumer_stack[CCNL_STACK_SIZE];
static msg_t _msg_queue[8];

#define MAIN_PERIODIC           (0x666)
static msg_t _wait_reset = { .type = MAIN_PERIODIC };
static xtimer_t _wait_timer = { .target = 0, .long_target = 0 };

extern int _ccnl_interest(int argc, char **argv);

void *_consumer_event_loop(void *arg)
{
    (void)arg;
    msg_init_queue(_msg_queue, 8);

    /* periodically request content items */
    char req_uri[20];
    int cnt = 0;
    char *a[2];
    xtimer_set_msg(&_wait_timer, DELAY_REQUEST, &_wait_reset, sched_active_pid);
    while(1){
        msg_t m;
        msg_receive(&m);
        if(m.type == MAIN_PERIODIC){
            snprintf(req_uri, 20, "/HAW/nodeid/%d", cnt++);
            a[1]= req_uri;
            _ccnl_interest(2, (char **)a);
            xtimer_set_msg(&_wait_timer, DELAY_REQUEST, &_wait_reset, sched_active_pid);
        }
    }
}


int main(void)
{
    uint16_t src_len = 8;
#ifdef MODULE_TLSF
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
#endif
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("ndn_vanilla");

    ccnl_core_init();

    ccnl_start();

    /* get the default interface */
    gnrc_netif_t *netif = gnrc_netif_iter(NULL);

    gnrc_netapi_set(netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
#ifdef MODULE_PKTCNT
    /* init pktcnt */
    if (pktcnt_init() != PKTCNT_OK) {
        puts("error: unable to initialize pktcnt");
        return 1;
    }
#endif

    /* set the relay's PID, configure the interface to use CCN nettype */
    if (ccnl_open_netif(netif->pid, GNRC_NETTYPE_CCN) < 0) {
        puts("Error registering at network interface!");
        return -1;
    }

#ifdef MODULE_GNRC_PKTDUMP
    gnrc_netreg_entry_t dump = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                          gnrc_pktdump_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &dump);
#endif

    /* set FIB manually */
    char fib_uri[] = {"/HAW"};
    char fib_addr[] = {"12:34:56:78:90:12"};
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(fib_uri, CCNL_SUITE_NDNTLV, NULL, 0);
    if (!prefix) {
        puts("Error: prefix could not be created!");
        return -1;
    }
    /* initialize address with 0xFF for broadcast */
    uint8_t relay_addr[GNRC_NETIF_L2ADDR_MAXLEN];
    memset(relay_addr, UINT8_MAX, GNRC_NETIF_L2ADDR_MAXLEN);
    size_t addr_len = gnrc_netif_addr_from_str(fib_addr, relay_addr);

    sockunion sun;
    sun.sa.sa_family = AF_PACKET;
    memcpy(&(sun.linklayer.sll_addr), relay_addr, addr_len);
    sun.linklayer.sll_halen = addr_len;
    sun.linklayer.sll_protocol = htons(ETHERTYPE_NDN);
    struct ccnl_face_s *fibface = ccnl_get_face_or_create(&ccnl_relay, 0, &(sun.sa), sizeof(sun.sa));
    if (fibface == NULL) {
        return -1;
    }
    fibface->flags |= CCNL_FACE_FLAGS_STATIC;

    if (ccnl_fib_add_entry(&ccnl_relay, prefix, fibface) != 0) {
        printf("Error adding to the FIB\n");
        return -1;
    }

    thread_create(_consumer_stack, sizeof(_consumer_stack),
                  CONSUMER_THREAD_PRIORITY,
                  THREAD_CREATE_STACKTEST, _consumer_event_loop,
                  NULL, "consumer");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
