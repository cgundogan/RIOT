/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdio.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "net/gnrc/netif.h"

#include "thread.h"
#include "xtimer.h"
#include "random.h"

#include "ccn-lite-riot.h"
#include "ccnl-pkt-builder.h"
#include "ccnl-callbacks.h"
#include "ccnl-producer.h"
#include "ccnl-qos.h"

#include "net/hopp/hopp.h"

#define MAIN_QSZ (4)
static msg_t _main_q[MAIN_QSZ];

uint8_t hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
bool i_am_root = false;

/* 10kB buffer for the heap should be enough for everyone */
#ifndef TLSF_BUFFER
#define TLSF_BUFFER     (10240)
#endif
static uint32_t _tlsf_heap[TLSF_BUFFER / sizeof(uint32_t)];

/* m3-289 */
#ifndef ROOTADDR
#define ROOTADDR "15:11:6B:10:65:FD:AC:52"
#endif
#ifndef ROOTPREFIX
#define ROOTPREFIX "/HK"
#endif
#ifndef CONSUMER_THREAD_PRIORITY
#define CONSUMER_THREAD_PRIORITY (THREAD_PRIORITY_MAIN - 1)
#endif
#ifndef HOPP_THREAD_PRIORITY
#define HOPP_THREAD_PRIORITY (THREAD_PRIORITY_MAIN - 2)
#endif
#ifndef CCNL_THREAD_PRIORITY
#define CCNL_THREAD_PRIORITY (THREAD_PRIORITY_MAIN - 3)
#endif

#ifndef DELAY_REQUEST
#define DELAY_REQUEST           (5 * 1000000) // us = 30sec
#endif

#ifndef DELAY_JITTER
#define DELAY_JITTER            (2 * 1000000) // us = 15sec
#endif

#define DELAY_MAX               (DELAY_REQUEST + DELAY_JITTER)
#define DELAY_MIN               (DELAY_REQUEST - DELAY_JITTER)

#ifndef REQ_DELAY
#define REQ_DELAY               (random_uint32_range(DELAY_MIN, DELAY_MAX))
#endif

static unsigned char int_buf[CCNL_MAX_PACKET_SIZE];
static unsigned char data_buf[CCNL_MAX_PACKET_SIZE];

static const char *rootaddr = ROOTADDR;

#define QOS_MAX_TC_ENTRIES (3)

static const qos_traffic_class_t tcs[QOS_MAX_TC_ENTRIES] =
{
    { "/HK", false, false },
    { "/HK/control", true, false },
    { "/HK/sensors", false, true },
};

int pit_strategy(struct ccnl_relay_s *relay, struct ccnl_interest_s *i)
{
    qos_traffic_class_t *tc = i->tc;

    struct ccnl_interest_s *oldest = NULL;

    printf("In PIT replacement, pit count: %d\n", relay->pitcnt);

    // (Reg, Reg)
    if (!tc->expedited && !tc->reliable) {
        // Drop
        return 0;
    }

    // (Reg, Rel)
    if (!tc->expedited && tc->reliable) {
        // Replace (Reg, Reg)
        struct ccnl_interest_s *cur = relay->pit;
        while (cur) {
            if (!cur->tc->expedited && !cur->tc->reliable) {
                if (!oldest || cur->last_used > oldest->last_used) {
                    oldest = cur;
                }
            }
            cur = cur->next;
        }

        if (oldest) {
            // Found a (Reg, Reg) entry to remove
            ccnl_interest_remove(relay, oldest);

            return 1;
        }

        // No (Reg, Reg) entry to remove
        return 0;

    }

    // (Exp, _)
    if (tc->expedited) {
        // Replace (Reg, _)
        struct ccnl_interest_s *cur = relay->pit;
        while (cur) {
            if (!cur->tc->expedited) {
                if (!oldest || cur->last_used > oldest->last_used) {
                    oldest = cur;
                }
            }
            cur = cur->next;
        }

        if (oldest) {
            // Found a (Reg, _) entry to remove
            ccnl_interest_remove(relay, oldest);

            return 1;
        }

        // No (Reg, _) entry to remove
        return 0;
    }

    return 0;
}

static int _root(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    hopp_root_start(rootaddr, strlen(rootaddr));
    i_am_root = true;
    return 0;
}

static int _publish(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    if (i_am_root) {
        return 0;
    }

    char name[30];
    int name_len = sprintf(name, "%s/sensors/%s", ROOTPREFIX, hwaddr_str);
    xtimer_usleep(random_uint32_range(0, 40000000));
    hopp_publish_content(name, name_len, NULL, 0);
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "hr", "start HoPP root", _root },
    { "hp", "publish data", _publish },
    { NULL, NULL, NULL }
};

static void cb_published(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt, struct ccnl_face_s *from)
{
    from->flags |= CCNL_FACE_FLAGS_STATIC;
    ccnl_fib_add_entry(relay, ccnl_prefix_dup(pkt->pfx), from);
}

static uint32_t _count_fib_entries(void) {
    int num_fib_entries = 0;
    struct ccnl_forward_s *fwd;
    for (fwd = ccnl_relay.fib; fwd; fwd = fwd->next) {
        num_fib_entries++;
    }
    return num_fib_entries;
}

static void *consumer_event_loop(void *arg)
{
    (void)arg;
    char req_uri[64];
    char s[CCNL_MAX_PREFIX_SIZE];
    struct ccnl_forward_s *fwd;
    int nodes_num = _count_fib_entries();
    uint32_t delay = 0;
    struct ccnl_prefix_s *prefix = NULL;

    printf("consumer_setup;%d\n",nodes_num);

    for (unsigned i = 0; i < 100; i++) {
        for (fwd = ccnl_relay.fib; fwd; fwd = fwd->next) {
            memset(int_buf, 0, 64);
            delay = (uint32_t)((float)REQ_DELAY/(float)nodes_num);
            xtimer_usleep(delay);
            ccnl_prefix_to_str(fwd->prefix,s,CCNL_MAX_PREFIX_SIZE);
            snprintf(req_uri, 64, "%s/%04d", s, i);
            printf("req;%s\n",req_uri);
            prefix = ccnl_URItoPrefix(req_uri, CCNL_SUITE_NDNTLV, NULL);
            ccnl_send_interest(fwd->prefix, int_buf, HOPP_INTEREST_BUFSIZE, NULL, NULL);
            ccnl_prefix_free(prefix);
        }
    }
    printf("consumer_done\n");

    return 0;
}
int produce_cont_and_cache(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt, int id)
{
    (void)pkt;
    char name[64];
    size_t offs = CCNL_MAX_PACKET_SIZE;

    char buffer[5];
    size_t len = sprintf(buffer, "%s", "24.5");
    buffer[len]='\0';

    int name_len = sprintf(name, "/%s/sensors/%s/%04d", ROOTPREFIX, hwaddr_str, id);
    name[name_len]='\0';

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL);
    size_t reslen = 0;
    ccnl_ndntlv_prependContent(prefix, (unsigned char*) buffer, len, NULL, NULL, &offs, data_buf, &reslen);

    ccnl_prefix_free(prefix);

    unsigned char *olddata;
    unsigned char *data = olddata = data_buf + offs;

    uint64_t typ;

    if (ccnl_ndntlv_dehead(&data, &reslen, &typ, &len) || typ != NDN_TLV_Data) {
        puts("ERROR in producer_func");
        return -1;
    }

    struct ccnl_content_s *c = 0;
    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &reslen);
    c = ccnl_content_new(&pk);
    ccnl_content_add2cache(relay, c);
    return 0;
}

int producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from, struct ccnl_pkt_s *pkt){
    (void) relay;
    (void) from;
    if(pkt->pfx->compcnt == 4) { /* /PREFIX/sensors/ID/<value> */
        /* match PREFIX and ID and "gasval" */
        if (!memcmp(pkt->pfx->comp[0], ROOTPREFIX, pkt->pfx->complen[0]) &&
            !memcmp(pkt->pfx->comp[1], "sensors", pkt->pfx->complen[1]) &&
            !memcmp(pkt->pfx->comp[2], hwaddr_str, pkt->pfx->complen[2])) {
            return produce_cont_and_cache(relay, pkt, atoi((const char *)pkt->pfx->comp[3]));
        }
    }
    return 0;
}

int main(void)
{
    tlsf_add_global_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_q, MAIN_QSZ);

    ccnl_core_init();

    ccnl_start();

    if (((hopp_netif = gnrc_netif_iter(NULL)) == NULL) ||
        (ccnl_open_netif(hopp_netif->pid, GNRC_NETTYPE_CCN) < 0)) {
        return -1;
    }

    uint16_t chan = 11;
    gnrc_netapi_set(hopp_netif->pid, NETOPT_CHANNEL, 0, &chan, sizeof(chan));

    uint16_t src_len = 8U;
    gnrc_netapi_set(hopp_netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
#ifdef BOARD_NATIVE
    gnrc_netapi_get(hopp_netif->pid, NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
#else
    gnrc_netapi_get(hopp_netif->pid, NETOPT_ADDRESS_LONG, 0, hwaddr, sizeof(hwaddr));
#endif
    gnrc_netif_addr_to_str(hwaddr, sizeof(hwaddr), hwaddr_str);

    hopp_pid = thread_create(hopp_stack, sizeof(hopp_stack), HOPP_THREAD_PRIORITY,
                             THREAD_CREATE_STACKTEST, hopp, &ccnl_relay, "hopp");

    if (hopp_pid <= KERNEL_PID_UNDEF) {
        return 1;
    }

    hopp_set_cb_published(cb_published);

    ccnl_qos_set_tcs((qos_traffic_class_t *) &tcs, sizeof(tcs) / sizeof(tcs[0]));

    ccnl_set_pit_strategy_remove(pit_strategy);

    printf("config;%d\n", ccnl_relay.max_pit_entries);

    if (memcmp(hwaddr_str, rootaddr, strlen(rootaddr)) == 0) {
        _root(0, NULL);
        xtimer_sleep(140);
    }
    else {
        ccnl_set_local_producer(producer_func);
        xtimer_sleep(10);
        _publish(0, NULL);
        xtimer_sleep(80);
    }

    printf("route;%s;%u\n", hwaddr_str, dodag.rank);

    msg_t msg = { .type = HOPP_STOP_MSG, .content.ptr = NULL };
    msg_send(&msg, hopp_pid);
    hopp_set_cb_published(NULL);

    if (i_am_root) {
        puts("starting consumer");
        memset(hopp_stack, 0, HOPP_STACKSZ);
        thread_create(hopp_stack, sizeof(hopp_stack),
                      CONSUMER_THREAD_PRIORITY, THREAD_CREATE_STACKTEST,
                      consumer_event_loop, NULL, "consumer");
    }

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
