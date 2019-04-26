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

#define QOS_MAX_TC_ENTRIES (3)

static const qos_traffic_class_t tcs[QOS_MAX_TC_ENTRIES] =
{
    { "/HAW", false, false },
    { "/SafetyIO/Site/A", false, true },
    { "/HAW/Room/481", true, true },
};

int pit_strategy(struct ccnl_relay_s *relay, struct ccnl_interest_s *i, qos_traffic_class_t *tc)
{
    (void) i;
    struct ccnl_interest_s *cur = relay->pit;
    struct ccnl_interest_s *oldest = NULL;

    printf("In PIT replacement tclass: [prefix: %s, reliable: %d, expedited: %d], pit count: %d\n",
           tc->traffic_class, tc->reliable, tc->expedited, relay->pitcnt);

    // (Reg, Reg)
    if (!tc->expedited && !tc->reliable) {
        // Drop
        return 0;
    }

    // (Reg, Rel)
    if (!tc->expedited && tc->reliable) {
        // Replace (Reg, Reg)
        while (cur) {
            if (!cur->tc->expedited && !cur->tc->reliable) {
                if (!oldest || cur->last_used < oldest->last_used) {
                    oldest = cur;
                }
            }
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
        while (cur) {
            if (!cur->tc->expedited) {
                if (!oldest || cur->last_used < oldest->last_used) {
                    oldest = cur;
                }
            }
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
    if (argc == 2) {
        hopp_root_start((const char *)argv[1], strlen(argv[1]));
        i_am_root = true;
    }
    else {
        puts("error");
        return -1;
    }
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
    int name_len = sprintf(name, "/%s/%s", argv[1], hwaddr_str);
    xtimer_usleep(random_uint32_range(0, 30000000));
    printf("RANK: %u\n", dodag.rank);
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
    static char scratch[32];
    struct ccnl_prefix_s *prefix;

    snprintf(scratch, sizeof(scratch)/sizeof(scratch[0]),
             "/%.*s/%.*s", pkt->pfx->complen[0], pkt->pfx->comp[0],
                           pkt->pfx->complen[1], pkt->pfx->comp[1]);
    printf("PUBLISHED: %s\n", scratch);
    prefix = ccnl_URItoPrefix(scratch, CCNL_SUITE_NDNTLV, NULL);

    from->flags |= CCNL_FACE_FLAGS_STATIC;
    ccnl_fib_add_entry(relay, ccnl_prefix_dup(prefix), from);
    ccnl_prefix_free(prefix);
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
    printf("hwaddr: %s\n", hwaddr_str);

    hopp_pid = thread_create(hopp_stack, sizeof(hopp_stack), THREAD_PRIORITY_MAIN - 1,
                             THREAD_CREATE_STACKTEST, hopp, &ccnl_relay,
                             "hopp");

    if (hopp_pid <= KERNEL_PID_UNDEF) {
        return 1;
    }

    hopp_set_cb_published(cb_published);

    ccnl_qos_set_tcs((qos_traffic_class_t *) &tcs, sizeof(tcs) / sizeof(tcs[0]));

    ccnl_set_pit_strategy_remove(pit_strategy);

    printf("max pit: %d\n", ccnl_relay.max_pit_entries);

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
