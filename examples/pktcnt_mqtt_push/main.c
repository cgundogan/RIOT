/*
 * Copyright (C) 2015 Freie Universität Berlin
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
 * @brief       Example application for demonstrating the RIOT network stack
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "fmt.h"
#include "shell.h"
#include "thread.h"
#include "xtimer.h"
#include "net/emcute.h"
#include "net/gnrc/netif.h"
#include "net/ipv6/addr.h"
#include "pktcnt.h"
#include "random.h"

#define EMCUTE_PRIO         (THREAD_PRIORITY_MAIN - 1)

#define I3_TOPIC            "/i3/gasval"
#ifndef I3_BROKER
#define I3_BROKER           { 0xaf, 0xfe, 0, 0, 0, 0, 0, 0, \
                              0, 0, 0, 0, 0, 0, 0, 1 }
#endif
#ifndef I3_MIN_WAIT
#define I3_MIN_WAIT (1)
#endif
#ifndef I3_MAX_WAIT
#define I3_MAX_WAIT (1)
#endif
#ifndef I3_MAX_REQ
#define I3_MAX_REQ      (3600U)
#endif
#define I3_PORT             EMCUTE_DEFAULT_PORT

#define PUB_GEN_STACK_SIZE (THREAD_STACKSIZE_MAIN)
#define PUB_GEN_PRIO       (THREAD_PRIORITY_MAIN - 1)

static char pub_gen_stack[PUB_GEN_STACK_SIZE];

static char mqtt_stack[THREAD_STACKSIZE_DEFAULT];
static const char *payload = "{\"id\":\"0x12a77af232\",\"val\":3000}";
static char client_id[(2 * GNRC_NETIF_L2ADDR_MAXLEN) + 1];
static sock_udp_ep_t gw = { .family = AF_INET6, .port = I3_PORT,
                            .addr = { .ipv6 = I3_BROKER } };
static emcute_topic_t t = { I3_TOPIC, 0 };
#ifdef I3_CONFIRMABLE
static const unsigned flags = EMCUTE_QOS_1;
#else
static const unsigned flags = EMCUTE_QOS_0;
#endif

static inline uint32_t _next_msg(void)
{
#if I3_MIN_WAIT < I3_MAX_WAIT
    return random_uint32_range(I3_MIN_WAIT * MS_PER_SEC,
                               I3_MAX_WAIT * MS_PER_SEC) * US_PER_MS;
#else
    return I3_MIN_WAIT * US_PER_SEC;
#endif
}

static void *pub_gen(void *arg)
{
    (void)arg;
    printf("pktcnt: MQTT-SN QoS%d push setup\n\n", (flags >> 5));
    for (unsigned i = 0; i < I3_MAX_REQ; i++) {
        xtimer_usleep(_next_msg());

        /* publish sensor data */
        if (emcute_pub(&t, payload, strlen(payload), flags) != EMCUTE_OK) {
            puts("error: failed to publish data");
        }
        else {
            puts("published sensor data");
        }

    }
    return NULL;
}

static void *emcute_thread(void *arg)
{
    (void)arg;
    emcute_run(I3_PORT, client_id);
    return NULL;    /* should never be reached */
}

static int pktcnt_start(int argc, char **argv)
{
    bool unbootstrapped = true;
    (void)argc;
    (void)argv;
    /* init pktcnt */
    /* wait for network to be set-up */
    while (unbootstrapped) {
        ipv6_addr_t addrs[GNRC_NETIF_IPV6_ADDRS_NUMOF];
        gnrc_netif_t *netif = gnrc_netif_iter(NULL);
        int res;

        xtimer_sleep(1);
        if (client_id[0] == '\0') {
            size_t res = fmt_bytes_hex(client_id, netif->l2addr, netif->l2addr_len);
            client_id[res] = '\0';
        }
        if ((res = gnrc_netif_ipv6_addrs_get(netif, addrs, sizeof(addrs))) > 0) {
            for (unsigned i = 0; i < (res / sizeof(ipv6_addr_t)); i++) {
                if (!ipv6_addr_is_link_local(&addrs[i])) {
                    char addr_str[IPV6_ADDR_MAX_STR_LEN];
                    printf("Global address %s configured\n",
                           ipv6_addr_to_str(addr_str, &addrs[i],
                                            sizeof(addr_str)));
                    unbootstrapped = false;
                    break;
                }
            }
        }
    }
    if (pktcnt_init() != PKTCNT_OK) {
        puts("error: unable to initialize pktcnt");
        return 1;
    }
    /* broker will sometimes approve connection but then say there was an
     * unexpected REGISTER */
    while (emcute_con(&gw, true, NULL, NULL, 0, flags) != EMCUTE_OK) {
        char ipv6_str[IPV6_ADDR_MAX_STR_LEN];
        printf("error: unable to connect to [%s]:%i\n",
               ipv6_addr_to_str(ipv6_str, (ipv6_addr_t *)&gw.addr,
                                sizeof(ipv6_str)), (int)gw.port);
        xtimer_usleep(random_uint32_range(EMCUTE_T_RETRY * US_PER_SEC,
                                          EMCUTE_T_RETRY * US_PER_SEC * 2));
    }
    puts("successfully connected to broker");
    /* now register out topic */
    while (emcute_reg(&t) != EMCUTE_OK) {
        puts("error: unable to register topic " I3_TOPIC "\n");
        xtimer_usleep(random_uint32_range(EMCUTE_T_RETRY * US_PER_SEC,
                                          EMCUTE_T_RETRY * US_PER_SEC * 2));
    }
    printf("successfully registered topic %s under ID %u\n", t.name, t.id);
    /* start the publishing thread */
    thread_create(pub_gen_stack, sizeof(pub_gen_stack), PUB_GEN_PRIO, 0,
                  pub_gen, NULL, "i3-pub-gen");

    return 0;
}

static const shell_command_t shell_commands[] = {
    { "pktcnt", "Start pktcnt", pktcnt_start },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* start the emcute thread */
    thread_create(mqtt_stack, sizeof(mqtt_stack), EMCUTE_PRIO, 0,
                  emcute_thread, NULL, "emcute");

    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
