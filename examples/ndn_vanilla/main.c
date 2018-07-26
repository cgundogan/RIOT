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
#define TLSF_BUFFER     ((42 * 1024)/ sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];
#endif

#ifndef PREFIX
#define PREFIX                   "i3"
#endif

#define I3_DATA     "{\"id\":\"0x12a77af232\",\"val\":3000}"

#ifndef NUM_REQUESTS_NODE
#define NUM_REQUESTS_NODE       (3600u)
#endif

#ifndef DELAY_REQUEST
#define DELAY_REQUEST           (30 * 1000000) // us = 30sec
#endif

#ifndef DELAY_JITTER
#define DELAY_JITTER            (15 * 1000000) // us = 15sec
#endif

#define DELAY_MAX               (DELAY_REQUEST + DELAY_JITTER)
#define DELAY_MIN               (DELAY_REQUEST - DELAY_JITTER)

#ifndef REQ_DELAY
#define REQ_DELAY               (random_uint32_range(DELAY_MIN, DELAY_MAX))
#endif

#ifndef CONSUMER_THREAD_PRIORITY
#define CONSUMER_THREAD_PRIORITY (THREAD_PRIORITY_MAIN - 1)
#endif

#ifndef HOPP_PRIO
#define HOPP_PRIO (HOPP_PRIO - 3)
#endif

uint8_t my_hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char my_hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
static unsigned char _out[CCNL_MAX_PACKET_SIZE];

static int my_macid = -1;
static char my_macid_str[4];

#define MACMAPSZ (367)
static const char macmap[MACMAPSZ][24] = {
"03:68:40:36:32:48:33:d6",
"03:80:31:36:32:48:33:d6",
"03:77:13:36:32:48:33:d2",
"03:68:32:36:32:48:33:de",
"03:81:19:36:32:48:33:da",
"02:60:21:36:32:48:33:d6",
"03:68:37:36:32:48:33:da",
"02:60:38:36:32:48:33:d6",
"03:79:30:36:32:48:33:de",
"03:68:25:36:32:48:33:da",
"03:79:24:36:32:48:33:de",
"03:83:39:36:32:48:33:da",
"03:68:30:36:32:48:33:d6",
"03:83:12:36:32:48:33:d6",
"03:82:40:36:32:48:33:de",
"03:67:11:36:32:48:33:d6",
"02:53:25:36:32:48:33:d6",
"02:53:25:36:32:48:33:d6",
"03:69:36:36:32:48:33:da",
"03:69:36:36:32:48:33:da",
"03:68:33:36:32:48:33:da",
"03:83:18:36:32:48:33:d6",
"03:82:26:36:32:48:33:de",
"03:76:21:36:32:48:33:da",
"03:76:11:36:32:48:33:da",
"03:68:38:36:32:48:33:da",
"03:82:19:36:32:48:33:de",
"02:54:23:36:32:48:33:d6",
"02:62:21:36:32:48:33:d6",
"03:83:19:36:32:48:33:da",
"03:68:29:36:32:48:33:da",
"03:72:15:36:32:48:33:d6",
"03:78:29:36:32:48:33:da",
"03:80:39:36:32:48:33:da",
"03:76:24:36:32:48:33:de",
"03:80:34:36:32:48:33:d6",
"03:72:28:36:32:48:33:da",
"03:78:12:36:32:48:33:da",
"03:75:42:36:32:48:33:de",
"03:80:27:36:32:48:33:da",
"03:83:36:36:32:48:33:da",
"03:76:41:36:32:48:33:da",
"03:83:34:36:32:48:33:d6",
"03:79:05:36:32:48:33:da",
"03:83:27:36:32:48:33:da",
"03:79:17:36:32:48:33:da",
"03:69:40:36:32:48:33:da",
"03:80:16:36:32:48:33:d6",
"03:68:26:36:32:48:33:d6",
"03:80:13:36:32:48:33:d2",
"03:83:14:36:32:48:33:da",
"03:78:24:36:32:48:33:da",
"03:70:04:36:32:48:33:da",
"03:81:24:36:32:48:33:d6",
"03:70:24:36:32:48:33:da",
"03:75:15:36:32:48:33:da",
"03:82:31:36:32:48:33:de",
"03:69:43:36:32:48:33:d6",
"03:81:25:36:32:48:33:d6",
"03:68:39:36:32:48:33:d6",
"02:62:05:36:32:48:33:da",
"03:68:35:36:32:48:33:de",
"03:77:33:36:32:48:33:d6",
"03:68:41:36:32:48:33:de",
"03:82:34:36:32:48:33:de",
"03:82:24:36:32:48:33:da",
"03:78:40:36:32:48:33:da",
"03:81:21:36:32:48:33:da",
"03:80:15:36:32:48:33:da",
"03:76:32:36:32:48:33:da",
"02:62:08:36:32:48:33:da",
"03:70:25:36:32:48:33:da",
"03:69:41:36:32:48:33:de",
"03:82:10:36:32:48:33:da",
"03:82:17:36:32:48:33:da",
"03:77:25:36:32:48:33:d6",
"03:70:03:36:32:48:33:da",
"03:79:29:36:32:48:33:d6",
"03:76:39:36:32:48:33:da",
"03:82:23:36:32:48:33:da",
"03:79:27:36:32:48:33:da",
"03:67:10:36:32:48:33:d6",
"03:71:07:36:32:48:33:d6",
"03:72:09:36:32:48:33:da",
"03:81:09:36:32:48:33:d6",
"03:71:21:36:32:48:33:d6",
"02:62:14:36:32:48:33:de",
"03:77:11:36:32:48:33:da",
"03:69:17:36:32:48:33:de",
"03:71:22:36:32:48:33:d6",
"03:71:24:36:32:48:33:da",
"03:77:12:36:32:48:33:d6",
"03:76:14:36:32:48:33:d6",
"03:76:26:36:32:48:33:da",
"03:67:07:36:32:48:33:d6",
"03:75:25:36:32:48:33:da",
"03:75:24:36:32:48:33:da",
"03:82:18:36:32:48:33:de",
"03:71:41:36:32:48:33:de",
"03:78:13:36:32:48:33:d6",
"03:80:32:36:32:48:33:da",
"03:72:04:36:32:48:33:da",
"03:67:15:36:32:48:33:d6",
"03:75:11:36:32:48:33:de",
"03:69:33:36:32:48:33:da",
"03:71:18:36:32:48:33:da",
"03:81:17:36:32:48:33:da",
"03:81:34:36:32:48:33:d6",
"03:79:34:36:32:48:33:de",
"03:67:13:36:32:48:33:de",
"03:72:06:36:32:48:33:d6",
"03:81:26:36:32:48:33:de",
"03:75:27:36:32:48:33:da",
"03:76:35:36:32:48:33:da",
"03:82:13:36:32:48:33:da",
"03:72:20:36:32:48:33:de",
"03:80:30:36:32:48:33:de",
"03:81:11:36:32:48:33:d6",
"03:81:28:36:32:48:33:da",
"03:81:18:36:32:48:33:da",
"03:77:04:36:32:48:33:da",
"02:62:10:36:32:48:33:d6",
"02:61:38:36:32:48:33:d6",
"03:79:07:36:32:48:33:da",
"03:76:38:36:32:48:33:da",
"03:79:33:36:32:48:33:da",
"03:76:10:36:32:48:33:da",
"03:81:20:36:32:48:33:da",
"03:80:23:36:32:48:33:de",
"02:61:18:36:32:48:33:da",
"03:79:22:36:32:48:33:da",
"03:69:37:36:32:48:33:d6",
"03:76:15:36:32:48:33:de",
"03:76:36:36:32:48:33:de",
"03:71:09:36:32:48:33:da",
"03:71:10:36:32:48:33:d6",
"03:76:04:36:32:48:33:da",
"03:77:30:36:32:48:33:da",
"03:82:33:36:32:48:33:de",
"03:76:43:36:32:48:33:da",
"03:72:27:36:32:48:33:de",
"03:77:24:36:32:48:33:da",
"03:79:18:36:32:48:33:da",
"03:82:32:36:32:48:33:da",
"03:77:27:36:32:48:33:da",
"03:82:27:36:32:48:33:da",
"03:76:17:36:32:48:33:d6",
"03:80:24:36:32:48:33:da",
"02:62:09:36:32:48:33:d6",
"03:82:12:36:32:48:33:d6",
"03:77:31:36:32:48:33:d6",
"03:82:09:36:32:48:33:da",
"02:60:16:36:32:48:33:d6",
"03:68:36:36:32:48:33:d6",
"03:76:18:36:32:48:33:d6",
"02:60:18:36:32:48:33:da",
"03:79:15:36:32:48:33:da",
"03:71:26:36:32:48:33:de",
"03:83:29:36:32:48:33:de",
"03:82:16:36:32:48:33:da",
"03:69:21:36:32:48:33:da",
"03:79:25:36:32:48:33:d6",
"03:81:30:36:32:48:33:da",
"03:69:14:36:32:48:33:d6",
"03:76:33:36:32:48:33:de",
"03:71:11:36:32:48:33:da",
"02:62:06:36:32:48:33:d6",
"03:68:31:36:32:48:33:d6",
"03:83:24:36:32:48:33:da",
"03:80:35:36:32:48:33:da",
"03:77:42:36:32:48:33:da",
"03:80:25:36:32:48:33:da",
"03:69:26:36:32:48:33:da",
"03:78:25:36:32:48:33:d6",
"03:72:03:36:32:48:33:d6",
"03:78:36:36:32:48:33:de",
"03:80:36:36:32:48:33:da",
"03:68:42:36:32:48:33:da",
"03:77:07:36:32:48:33:d6",
"03:78:07:36:32:48:33:da",
"03:76:13:36:32:48:33:de",
"03:72:10:36:32:48:33:d6",
"03:80:14:36:32:48:33:de",
"03:68:11:36:32:48:33:da",
"03:78:19:36:32:48:33:da",
"03:79:09:36:32:48:33:d6",
"02:62:07:36:32:48:33:d6",
"03:83:35:36:32:48:33:de",
"03:71:16:36:32:48:33:d6",
"02:62:18:36:32:48:33:da",
"03:68:19:36:32:48:33:da",
"03:69:11:36:32:48:33:da",
"03:81:32:36:32:48:33:de",
"03:75:07:36:32:48:33:d6",
"03:76:12:36:32:48:33:de",
"03:80:18:36:32:48:33:da",
"03:82:15:36:32:48:33:da",
"03:79:23:36:32:48:33:d6",
"03:67:09:36:32:48:33:d6",
"03:77:38:36:32:48:33:da",
"03:84:15:36:32:48:33:d6",
"03:83:21:36:32:48:33:da",
"03:75:04:36:32:48:33:d6",
"03:76:22:36:32:48:33:de",
"03:69:35:36:32:48:33:da",
"02:62:13:36:32:48:33:d2",
"03:72:11:36:32:48:33:da",
"03:71:20:36:32:48:33:da",
"02:62:22:36:32:48:33:da",
"03:69:09:36:32:48:33:da",
"03:71:04:36:32:48:33:da",
"03:79:28:36:32:48:33:da",
"03:78:20:36:32:48:33:da",
"03:83:11:36:32:48:33:da",
"03:75:14:36:32:48:33:d6",
"03:69:06:36:32:48:33:da",
"03:67:14:36:32:48:33:d6",
"03:69:10:36:32:48:33:d6",
"03:79:20:36:32:48:33:d6",
"03:68:18:36:32:48:33:da",
"02:61:35:36:32:48:33:da",
"02:60:30:36:32:48:33:de",
"03:69:34:36:32:48:33:da",
"02:60:33:36:32:48:33:d6",
"03:67:06:36:32:48:33:da",
"02:54:26:36:32:48:33:da",
"03:83:38:36:32:48:33:da",
"02:53:29:36:32:48:33:da",
"03:67:05:36:32:48:33:da",
"03:81:40:36:32:48:33:da",
"03:80:19:36:32:48:33:d6",
"03:83:17:36:32:48:33:da",
"03:75:08:36:32:48:33:da",
"03:80:21:36:32:48:33:da",
"03:76:42:36:32:48:33:de",
"03:69:24:36:32:48:33:da",
"03:72:05:36:32:48:33:da",
"03:69:32:36:32:48:33:da",
"03:71:06:36:32:48:33:d6",
"03:72:17:36:32:48:33:da",
"03:72:16:36:32:48:33:da",
"03:69:25:36:32:48:33:de",
"03:69:28:36:32:48:33:da",
"03:71:19:36:32:48:33:d6",
"03:72:07:36:32:48:33:da",
"03:72:21:36:32:48:33:da",
"03:69:22:36:32:48:33:d6",
"03:80:42:36:32:48:33:da",
"03:69:18:36:32:48:33:da",
"03:79:36:36:32:48:33:da",
"03:82:35:36:32:48:33:d6",
"03:70:05:36:32:48:33:da",
"03:77:26:36:32:48:33:da",
"02:62:15:36:32:48:33:d6",
"03:81:14:36:32:48:33:de",
"02:62:23:36:32:48:33:da",
"03:72:23:36:32:48:33:da",
"03:81:08:36:32:48:33:da",
"03:77:14:36:32:48:33:de",
"03:68:16:36:32:48:33:d6",
"03:79:32:36:32:48:33:de",
"03:68:14:36:32:48:33:da",
"03:72:24:36:32:48:33:da",
"03:82:37:36:32:48:33:da",
"03:78:21:36:32:48:33:da",
"03:78:05:36:32:48:33:de",
"03:83:20:36:32:48:33:de",
"03:82:30:36:32:48:33:de",
"03:78:26:36:32:48:33:da",
"03:77:10:36:32:48:33:d6",
"03:71:03:36:32:48:33:d6",
"02:61:37:36:32:48:33:da",
"03:82:29:36:32:48:33:da",
"03:81:38:36:32:48:33:de",
"03:69:12:36:32:48:33:de",
"03:68:24:36:32:48:33:da",
"03:83:15:36:32:48:33:d6",
"03:83:33:36:32:48:33:da",
"03:77:34:36:32:48:33:da",
"03:81:16:36:32:48:33:d6",
"03:76:19:36:32:48:33:da",
"03:83:16:36:32:48:33:da",
"03:77:05:36:32:48:33:da",
"03:77:06:36:32:48:33:d2",
"03:78:18:36:32:48:33:d6",
"03:80:41:36:32:48:33:de",
"03:68:20:36:32:48:33:da",
"04:83:13:36:32:48:33:d6",
"03:72:14:36:32:48:33:da",
"03:80:37:36:32:48:33:d6",
"03:78:33:36:32:48:33:da",
"03:69:05:36:32:48:33:da",
"03:83:23:36:32:48:33:da",
"03:76:23:36:32:48:33:da",
"03:79:35:36:32:48:33:d6",
"03:72:08:36:32:48:33:d6",
"03:82:38:36:32:48:33:da",
"03:72:29:36:32:48:33:da",
"03:68:27:36:32:48:33:da",
"03:70:26:36:32:48:33:de",
"03:70:28:36:32:48:33:de",
"03:79:21:36:32:48:33:de",
"02:61:30:36:32:48:33:da",
"03:80:17:36:32:48:33:de",
"03:79:13:36:32:48:33:da",
"03:76:40:36:32:48:33:da",
"03:81:13:36:32:48:33:da",
"03:78:16:36:32:48:33:da",
"02:61:28:36:32:48:33:de",
"03:79:12:36:32:48:33:da",
"03:80:33:36:32:48:33:de",
"03:80:29:36:32:48:33:de",
"03:76:27:36:32:48:33:de",
"03:81:22:36:32:48:33:da",
"03:80:28:36:32:48:33:da",
"03:71:17:36:32:48:33:da",
"03:82:39:36:32:48:33:da",
"03:69:29:36:32:48:33:da",
"03:83:25:36:32:48:33:d6",
"03:75:18:36:32:48:33:da",
"03:81:37:36:32:48:33:da",
"03:83:22:36:32:48:33:d2",
"03:82:25:36:32:48:33:de",
"03:81:33:36:32:48:33:da",
"03:70:43:36:32:48:33:de",
"02:62:11:36:32:48:33:de",
"03:79:14:36:32:48:33:d6",
"03:82:20:36:32:48:33:da",
"03:77:08:36:32:48:33:da",
"03:71:08:36:32:48:33:d6",
"03:71:12:36:32:48:33:da",
"03:70:23:36:32:48:33:da",
"03:76:08:36:32:48:33:da",
"03:75:26:36:32:48:33:de",
"03:83:30:36:32:48:33:da",
"03:68:43:36:32:48:33:da",
"03:82:14:36:32:48:33:da",
"02:62:17:36:32:48:33:da",
"03:75:17:36:32:48:33:d6",
"03:77:40:36:32:48:33:d6",
"03:75:20:36:32:48:33:da",
"03:84:14:36:32:48:33:da",
"03:75:21:36:32:48:33:de",
"02:54:22:36:32:48:33:da",
"03:75:05:36:32:48:33:de",
"02:60:34:36:32:48:33:da",
"03:71:40:36:32:48:33:da",
"03:77:32:36:32:48:33:da",
"03:69:30:36:32:48:33:da",
"02:60:39:36:32:48:33:da",
"03:78:30:36:32:48:33:da",
"02:62:16:36:32:48:33:d6",
"03:78:28:36:32:48:33:d6",
"03:79:31:36:32:48:33:da",
"03:68:34:36:32:48:33:d6",
"03:70:27:36:32:48:33:de",
"02:60:29:36:32:48:33:da",
"03:78:27:36:32:48:33:da",
"03:69:31:36:32:48:33:da",
"03:69:13:36:32:48:33:d6",
"03:72:22:36:32:48:33:da",
"02:60:23:36:32:48:33:da",
"03:69:23:36:32:48:33:da",
"02:61:17:36:32:48:33:d6",
"03:69:20:36:32:48:33:da",
"03:71:13:36:32:48:33:da",
"03:69:16:36:32:48:33:d6",
};

/* state for running pktcnt module */
uint8_t pktcnt_running = 0;

extern int _ccnl_interest(int argc, char **argv);

static uint32_t _count_fib_entries(void) {
    int num_fib_entries = 0;
    struct ccnl_forward_s *fwd;
    for (fwd = ccnl_relay.fib; fwd; fwd = fwd->next) {
        num_fib_entries++;
    }
    return num_fib_entries;
}

void *_consumer_event_loop(void *arg)
{
    (void)arg;
    /* periodically request content items */
    char req_uri[40];
    char *a[2];
    char s[CCNL_MAX_PREFIX_SIZE];
    struct ccnl_forward_s *fwd;
    int nodes_num = _count_fib_entries();
    uint32_t delay = 0;
    for (unsigned i=0; i<NUM_REQUESTS_NODE; i++) {
        for (fwd = ccnl_relay.fib; fwd; fwd = fwd->next) {
            delay = (uint32_t)((float)REQ_DELAY/(float)nodes_num);
            xtimer_usleep(delay);
            ccnl_prefix_to_str(fwd->prefix,s,CCNL_MAX_PREFIX_SIZE);
            snprintf(req_uri, 40, "%s/gasval/%04d", s, i);
            a[1]= req_uri;
            _ccnl_interest(2, (char **)a);
        }
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
    /* unset local producer function for consumer node */
    ccnl_set_local_producer(NULL);
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

    if(pkt->pfx->compcnt == 4) { // /PREFIX/NODE_NAME/gasval/BLA
        /* match PREFIX and ID and "gasval*/
        if (!memcmp(pkt->pfx->comp[0], PREFIX, pkt->pfx->complen[0]) &&
            !memcmp(pkt->pfx->comp[1], my_macid_str, pkt->pfx->complen[1]) &&
            !memcmp(pkt->pfx->comp[2], "gasval", pkt->pfx->complen[2])) {

            char name[40];
            int offs = CCNL_MAX_PACKET_SIZE;

            char buffer[33];
            int len = sprintf(buffer, "%s", I3_DATA);
            buffer[len]='\0';

            int name_len = sprintf(name, "/%s/%s/gasval/%.*s", PREFIX, my_macid_str,
                pkt->pfx->complen[3], pkt->pfx->comp[3]);
            name[name_len]='\0';

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
    hopp_root_start(name, name_len);
    return 0;
}

static int _hopp_end(int argc, char **argv) {
    (void)argc;
    (void)argv;
    uint32_t the_fib_count = _count_fib_entries();
    printf("FIBCOUNT: %"PRIu32"\n", the_fib_count);
#ifdef MODULE_HOPP
    msg_t msg = { .type = HOPP_STOP_MSG, .content.ptr = NULL };
    int ret = msg_send(&msg, hopp_pid);
    if (ret <= 0) {
        printf("Error sending HOPP_STOP_MSG message to %d. ret=%d\n", hopp_pid, ret);
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
    printf("PUBLISHED: %s\n", scratch);
    prefix = ccnl_URItoPrefix(scratch, CCNL_SUITE_NDNTLV, NULL, NULL);

    from->flags |= CCNL_FACE_FLAGS_STATIC;
    int ret = ccnl_fib_add_entry(relay, ccnl_prefix_dup(prefix), from);
    if (ret != 0) {
        puts("FIB FULL");
    }
    ccnl_prefix_free(prefix);
}

static int _publish(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char name[30];
    int name_len = sprintf(name, "/%s/%s", PREFIX, my_macid_str);
    xtimer_usleep(random_uint32_range(0, 10000000));
    printf("RANK: %u\n", dodag.rank);
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
    { "req_start", "start periodic content requests", _req_start },
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

    for (int i = 0; i < MACMAPSZ; i++) {
        if (!strcmp(my_hwaddr_str, macmap[i])) {
            my_macid = i;
            break;
        }
    }

    snprintf(my_macid_str, sizeof(my_macid_str), "%03d", my_macid);

    printf("hwaddr: %s, macid: %s\n", my_hwaddr_str, my_macid_str);

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
