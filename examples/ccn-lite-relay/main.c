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

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (1)
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

static char name[8];
static const char *original = "/HAW/sensor/temp";
static const unsigned char content[512] = { 0x41 };

static unsigned char md[32];
static int mdlength = 32;

void ccnl_hmac256_sign(unsigned char *keyval, int kvlen,
                  unsigned char *data, int dlen,
                  unsigned char *md, int *mlen);

void measure(unsigned content_len)
{
    for (int i=0; i < 1000; ++i) {
        memcpy(name, original, strlen(original));
        uint64_t diff = xtimer_now_usec64();
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, NULL);
        struct ccnl_content_s *c = ccnl_mkContentObject(prefix, (unsigned char *)content, content_len, keyval, keyid);
        diff = xtimer_now_usec64() - diff;
        printf("0,%u,%lu\n", content_len, (unsigned long) diff);
        diff = xtimer_now_usec64();
        ccnl_hmac256_sign(keyval, 64, c->pkt->hmacStart, c->pkt->hmacLen, md, &mdlength);
        int res = memcmp(&md, c->pkt->hmacSignature, sizeof(md));
        diff = xtimer_now_usec64() - diff;
        if (res) {
            printf("2,%u,%lu\n", content_len, (unsigned long) diff);
        }
        else {
            printf("1,%u,%lu\n", content_len, (unsigned long) diff);
        }
        ccnl_prefix_free(prefix);
        if (c->pkt) {
            ccnl_prefix_free(c->pkt->pfx);
            ccnl_free(c->pkt->buf);
            ccnl_free(c->pkt);
        }
        ccnl_free(c);
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

    for (unsigned i=0; i <= 512; i+=1) {
        measure(i);
    }

    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
