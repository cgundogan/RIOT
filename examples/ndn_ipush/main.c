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
#include "net/gnrc/netif.h"
#include "net/gnrc/pktdump.h"
#include "pktcnt.h"
#include "xtimer.h"

#include "ccn-lite-riot.h"
#include "ccnl-pkt-builder.h"
#include "net/hopp/hopp.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#ifdef MODULE_TLSF
/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (46080 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];
#endif

#ifndef PREFIX
#define PREFIX                   "i3"
#endif

#define I3_DATA     "{\"id\":\"0x12a77af232\",\"val\":3000}"

#ifndef NUM_PUBLISHES_NODE
#define NUM_PUBLISHES_NODE      (3600u)
#endif

#ifndef DELAY_REQUEST
#define DELAY_REQUEST           (1000000u) // us = 1sec
#endif

#ifndef DELAY_JITTER
#define DELAY_JITTER            (250000) // us = 0,25sec
#endif

#define DELAY_MAX               (DELAY_REQUEST + DELAY_JITTER)
#define DELAY_MIN               (DELAY_REQUEST - DELAY_JITTER)

#ifndef CONSUMER_THREAD_PRIORITY
#define CONSUMER_THREAD_PRIORITY (THREAD_PRIORITY_MAIN - 1)
#endif

#ifndef HOPP_PRIO
#define HOPP_PRIO (HOPP_PRIO - 3)
#endif

#ifdef MODULE_IEEE802154
/* hwaddr of m3-34 in grenoble */
#define HWADDR_CONSUMER         "03:68:39:36:32:48:33:d6"
#else
/* use this for native */
//#define HWADDR_CONSUMER         "12:34:56:78:90:12"
#define HWADDR_CONSUMER         "ff:ff:ff:ff:ff:ff"
#endif

uint8_t my_hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char my_hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
static bool i_am_root = false;


/* state for running pktcnt module */
uint8_t pktcnt_running = 0;

extern int _ccnl_interest(int argc, char **argv);


void *_consumer_event_loop(void *arg)
{
    (void)arg;
    /* periodically request content items */
    char req_uri[100];
    char *a[2];
    for (unsigned i=0; i<NUM_PUBLISHES_NODE; i++) {
        xtimer_usleep(random_uint32_range(DELAY_MIN, DELAY_MAX));
        snprintf(req_uri, 100, "/%s/%s/gasval/%04d/%s", PREFIX, my_hwaddr_str, i, I3_DATA);
        //printf("push : %s\n size of string: %i\n", req_uri, strlen(req_uri));
        a[1]= req_uri;
        _ccnl_interest(2, (char **)a);
    }
    return 0;
}

static int _req_start(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (!pktcnt_running) {
        puts("Warning: pktcnt module not running");
    }

    if (i_am_root) {
        return 0;
    }
    /* unset local producer function for producer nodes */
    ccnl_set_local_producer(NULL);

    /* Attention! We re-use the HOPP stack as this thread is done here */
    memset(hopp_stack, 0, HOPP_STACKSZ);
    thread_create(hopp_stack, sizeof(hopp_stack),
                  CONSUMER_THREAD_PRIORITY,
                  THREAD_CREATE_STACKTEST, _consumer_event_loop,
                  NULL, "consumer");
    return 0;
}

static int _pktcnt_start(int argc, char **argv) {
    (void)argc;
    (void)argv;
#ifdef MODULE_PKTCNT
    /* init pktcnt */
    if (pktcnt_init() != PKTCNT_OK) {
        puts("error: unable to initialize pktcnt");
        return 1;
    }
    pktcnt_running=1;
#endif
    return 0;
}

int producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                   struct ccnl_pkt_s *pkt){
    (void)from;

/*    printf("%.*s ; %.*s ;%.*s ;%.*s ;%.*s\n", pkt->pfx->complen[0], pkt->pfx->comp[0], 
                                              pkt->pfx->complen[1], pkt->pfx->comp[1], 
                                              pkt->pfx->complen[2], pkt->pfx->comp[2], 
                                              pkt->pfx->complen[3], pkt->pfx->comp[3], 
                                              pkt->pfx->complen[4], pkt->pfx->comp[4]);*/

    if(pkt->pfx->compcnt == 5) { // /PREFIX/NODE_NAME/gasval/BLA/I3_DATA
        /* match PREFIX and ID and "gasval*/
        if (!memcmp(pkt->pfx->comp[0], PREFIX, pkt->pfx->complen[0]) &&
            !memcmp(pkt->pfx->comp[2], "gasval", pkt->pfx->complen[2]) 
            &&!memcmp(pkt->pfx->comp[4], I3_DATA, pkt->pfx->complen[4])) {

            int len = 4;
            char buffer[len];
            snprintf(buffer, len, "ACK");
            unsigned char *b = (unsigned char *)buffer;
            struct ccnl_content_s *c = ccnl_mkContentObject(pkt->pfx, b, len, NULL);
            c->last_used -= CCNL_CONTENT_TIMEOUT + 5;
            if (c) {
                ccnl_content_add2cache(relay, c);
            }
        }
    }
    return 0;
}

static int _root(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char name[5];
    int name_len = sprintf(name, "/%s", PREFIX);

    i_am_root = true;

    hopp_root_start(name, name_len);
    return 0;
}

static int _hopp_end(int argc, char **argv) {
    (void)argc;
    (void)argv;
#ifdef MODULE_HOPP
    msg_t msg = { .type = HOPP_STOP_MSG, .content.ptr = NULL };
    if (msg_send(&msg, hopp_pid) <= 0) {
        puts("Error sending HOPP_STOP_MSG message");
        return 1;
    }
#endif
    return 0;
}


static void cb_published(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt,
                         struct ccnl_face_s *from)
{
    static char scratch[32];
    struct ccnl_prefix_s *prefix;


    snprintf(scratch, sizeof(scratch)/sizeof(scratch[0]),
             "/%.*s/%.*s", pkt->pfx->complen[0], pkt->pfx->comp[0],
                           pkt->pfx->complen[1], pkt->pfx->comp[1]);
    //printf("PUBLISHED: %s\n", scratch);
    prefix = ccnl_URItoPrefix(scratch, CCNL_SUITE_NDNTLV, NULL, NULL);

    from->flags |= CCNL_FACE_FLAGS_STATIC;
    ccnl_fib_add_entry(relay, ccnl_prefix_dup(prefix), from);
    ccnl_prefix_free(prefix);
}

static int _publish(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char name[30];
    int name_len = sprintf(name, "/%s/%s", PREFIX, my_hwaddr_str);
    if(!hopp_publish_content(name, name_len, NULL, 0)) {
        return 1;
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "hr", "start HoPP root", _root },
    { "hp", "publish data", _publish },
    { "he", "HoPP end", _hopp_end },
    { "pktcnt_start", "start pktcnt module", _pktcnt_start },
    { "req_start", "start periodic publishes", _req_start },
    { NULL, NULL, NULL }
};

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

    uint16_t chan = 11;
    gnrc_netapi_set(netif->pid, NETOPT_CHANNEL, 0, &chan, sizeof(chan));

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

    ccnl_set_local_producer(producer_func);
    /* save hw address globally */
#ifdef BOARD_NATIVE
    gnrc_netapi_get(netif->pid, NETOPT_ADDRESS, 0, my_hwaddr, sizeof(my_hwaddr));
#else
    gnrc_netapi_get(netif->pid, NETOPT_ADDRESS_LONG, 0, my_hwaddr, sizeof(my_hwaddr));
#endif
    gnrc_netif_addr_to_str(my_hwaddr, sizeof(my_hwaddr), my_hwaddr_str);
    printf("My ID is: %s\n", my_hwaddr_str);

#ifdef MODULE_HOPP
    hopp_netif = netif;
    hopp_pid = thread_create(hopp_stack, sizeof(hopp_stack), HOPP_PRIO,
                             THREAD_CREATE_STACKTEST, hopp, &ccnl_relay,
                             "hopp");

    if (hopp_pid <= KERNEL_PID_UNDEF) {
        return 1;
    }

    hopp_set_cb_published(cb_published);
#endif

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
