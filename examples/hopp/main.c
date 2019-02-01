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
// #include "shell.h"
#include "net/gnrc/netif.h"

#include "thread.h"
#include "xtimer.h"
#include "random.h"

#include "ccn-lite-riot.h"
#include "ccnl-pkt-builder.h"
#include "ccnl-callbacks.h"

#include "net/hopp/hopp.h"

#define MAIN_QSZ (4)
static msg_t _main_q[MAIN_QSZ];

uint8_t hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];

/*
static int _root(int argc, char **argv)
{
    if (argc == 2) {
        hopp_root_start((const char *)argv[1], strlen(argv[1]));
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

static int _publish(int argc, char **argv)
{
    if (argc == 2) {
        hopp_publish_content((const char *)argv[1], strlen(argv[1]), NULL, 0);
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "hr", "start HoPP root", _root },
    { "hp", "publish data", _publish },
    { NULL, NULL, NULL }
};
*/

void cb_published(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt, struct ccnl_face_s *from)
{
    (void) relay;
    (void) from;
    static int onoff_state = 0;

    char payload[16];
    int payload_int = 0;

    char *s = ccnl_prefix_to_path(pkt->pfx);
    printf("PUB;%s;%.*s\n", s, pkt->contlen, pkt->content);

    memcpy(payload, pkt->content, pkt->contlen);
    payload[pkt->contlen] = '\0';

    payload_int = atoi(payload);

    char prefix_fan[32];
    int prefix_len = sprintf(prefix_fan, "/i3/fan/%u", (unsigned)xtimer_now_usec());
    prefix_fan[prefix_len]='\0';
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(prefix_fan, CCNL_SUITE_NDNTLV, NULL);
    if (payload_int >= 285) {
        onoff_state = 1;
        char content[1] = "1";
        struct ccnl_content_s *c = ccnl_mkContentObject(prefix, (unsigned char *)content, 1, NULL);
        c->flags |= CCNL_CONTENT_FLAGS_STATIC;
        ccnl_cs_add(relay, c);
    }
    else if (onoff_state && (payload_int < 285)) {
        onoff_state = 0;
        char content[1] = "0";
        struct ccnl_content_s *c = ccnl_mkContentObject(prefix, (unsigned char *)content, 1, NULL);
        c->flags |= CCNL_CONTENT_FLAGS_STATIC;
        ccnl_cs_add(relay, c);
    }
    ccnl_prefix_free(prefix);
    ccnl_free(s);
}

int _on_data2(struct ccnl_relay_s *relay, struct ccnl_content_s *c)
{
    (void) c;
    char *prefix_fan = "/i3/fan";
    struct ccnl_content_s *con = relay->contents, *con2;
    while(con) {
        con2 = con->next;
        char *s = ccnl_prefix_to_path(con->pkt->pfx);
        if (!memcmp(s, prefix_fan, strlen(prefix_fan))) {
            ccnl_content_remove(relay, con);
        }
        ccnl_free(s);
        con = con2;
    }
    return 0;
}

int main(void)
{
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

    hopp_pid = thread_create(hopp_stack, sizeof(hopp_stack), THREAD_PRIORITY_MAIN - 1,
                             THREAD_CREATE_STACKTEST, hopp, &ccnl_relay,
                             "hopp");

    if (hopp_pid <= KERNEL_PID_UNDEF) {
        return 1;
    }

    hopp_set_cb_published(cb_published);

    ccnl_set_cb_tx_on_data2(_on_data2);

#ifdef HOPP_ROOT
    hopp_root_start("/i3", 3);
#endif

    /*
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    */
    while(1);

    return 0;
}
