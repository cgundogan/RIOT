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

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#ifdef MODULE_TLSF
/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (20240 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];
#endif

#ifndef PREFIX
#define PREFIX                   "HAW"
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

uint8_t my_hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char my_hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
static unsigned char _out[CCNL_MAX_PACKET_SIZE];

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

static int _req_start(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    /* unset local producer function for consumer node */
    ccnl_set_local_producer(NULL);
    /* set FIB manually */
    char fib_uri[] = {"/HAW"};
    //char fib_addr[] = {"12:34:56:78:90:12:99:99"};
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
    return 0;
}

int producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                   struct ccnl_pkt_s *pkt){
    (void)from;

    if(pkt->pfx->compcnt == 2) { // /PREFIX/NODE_NAME
        /* match PREFIX and ID */
        if (!memcmp(pkt->pfx->comp[0], PREFIX, pkt->pfx->complen[0]) &&
            !memcmp(pkt->pfx->comp[1], my_hwaddr_str, pkt->pfx->complen[1])) {
            //printf("NUM CMPS %i MATCH PFX AND ID\n", (int)pkt->pfx->compcnt);

            char name[32], name2[32];
            int offs = CCNL_MAX_PACKET_SIZE;

            char buffer[20];
            uint32_t now = xtimer_now_usec();
            int len = sprintf(buffer, "%"PRIu32, now);
            buffer[len]='\0';

            unsigned time = (unsigned)xtimer_now_usec();
            int name_len = sprintf(name, "/%s/%s/%u", PREFIX, my_hwaddr_str, time);
            name[name_len]='\0';
            memcpy(name2, name, name_len);
            name2[name_len]='\0';

            struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, NULL);
            int arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) buffer,
                len, NULL, NULL, &offs, _out);

            ccnl_prefix_free(prefix);

            unsigned char *olddata;
            unsigned char *data = olddata = _out + offs;

            unsigned typ;

            if (ccnl_ndntlv_dehead(&data, &arg_len, (int*) &typ, &len) || typ != NDN_TLV_Data) {
                puts("ERROR in producer_func");
                return false;
            }

            struct ccnl_content_s *c = 0;
            struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &arg_len);
            c = ccnl_content_new(&pk);
            ccnl_content_add2cache(relay, c);
            c->flags |= CCNL_CONTENT_FLAGS_STATIC;

/*            char buffer[20];
            uint32_t now = xtimer_now_usec();
            int len = snprintf(buffer, 20, "%"PRIu32, now);
            //int len = snprintf(buffer, 20, "hello world");
            struct ccnl_content_s *c = ccnl_mkContentObject(pkt->pfx, (unsigned char *)buffer, len, NULL);
            printf("GEN CONT ON THE FLY: %s time was now: %"PRIu32 " and content pointer: %p len: %i\n", buffer, now, (void *)c, len);
            //c->last_used -= CCNL_CONTENT_TIMEOUT + 5;
            c->flags |= CCNL_CONTENT_FLAGS_STALE;
            if (c) {
                ccnl_content_add2cache(relay, c);
            }*/
        }
    }
    return 0;
}


static const shell_command_t shell_commands[] = {
    { "req_start", "start periodic content requests", _req_start },
    //{ "prod_start", "set local producer function", _prod_start },
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

    ccnl_set_local_producer(producer_func);
    /* save hw address globally */
#ifdef BOARD_NATIVE
    gnrc_netapi_get(netif->pid, NETOPT_ADDRESS, 0, my_hwaddr, sizeof(my_hwaddr));
#else
    gnrc_netapi_get(netif->pid, NETOPT_ADDRESS_LONG, 0, my_hwaddr, sizeof(my_hwaddr));
#endif
    gnrc_netif_addr_to_str(my_hwaddr, sizeof(my_hwaddr), my_hwaddr_str);
    printf("My ID is: %s\n", my_hwaddr_str);

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
