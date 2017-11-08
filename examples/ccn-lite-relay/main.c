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
#include <string.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "ccn-lite-riot.h"
#include "net/gnrc/netif.h"

#include "ccnl-pkt-builder.h"
#include "net/gnrc/netapi.h"

#include "xtimer.h"
#include "ps.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (10240 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

#ifdef USE_HMAC256
// choose a key that is at least 32 bytes long
static const char *secret_key = "some secret secret secret secret";
#endif
static unsigned char keyval[64];
static unsigned char keyid[32];

static char name[512];
static const char content[512] = { 0x41 };

void measure(unsigned name_len, unsigned content_len)
{
    for (int i=0; i < 1000; ++i) {
        memset(name, 0x41, sizeof(name)/sizeof(name[0]));
        name[name_len] = '\0';
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, NULL);
        struct ccnl_content_s *c = ccnl_mkContentObject(prefix, (unsigned char *)content, content_len, keyval, keyid);
        free_prefix(prefix);
        if (c) {
            ccnl_content_add2cache(&ccnl_relay, c);
        }
    }
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

#ifdef USE_HMAC256
    ccnl_hmac256_keyval((unsigned char*)secret_key,
                        strlen(secret_key), keyval);
    ccnl_hmac256_keyid((unsigned char*)secret_key,
                        strlen(secret_key), keyid);
#endif

    /* set the relay's PID, configure the interface to use CCN nettype */
    if ((gnrc_netif_get(ifs) == 0) || (ccnl_open_netif(ifs[0], GNRC_NETTYPE_CCN) < 0)) {
        puts("Error registering at network interface!");
        return -1;
    }

    char line_buf[SHELL_DEFAULT_BUFSIZE];

    for (unsigned i=0; i < 129; i+=8) {
        printf("3,%u,", i);
        uint32_t time = xtimer_now_usec();
        measure(3,i);
        time = xtimer_now_usec() - time;
        printf("%" PRIu32 "\n", time);
        //ps();
    }
    ccnl_cs_dump(&ccnl_relay);

    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
