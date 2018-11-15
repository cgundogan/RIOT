#include <stdio.h>
#include "msg.h"

#include "net/gcoap.h"
#include "kernel_types.h"
#include "shell.h"
#include "net/gnrc/ipv6/nib.h"

#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#if defined (NODE_CONSUMER) || defined (NODE_PRODUCER)
static ipv6_addr_t dst_ipv6_addr;
#endif

#ifndef MAX_REQS
#define MAX_REQS (10000U)
#endif

#ifndef DELAY
#define DELAY (100U * 1000U)
#endif

#ifndef URI
#define URI "/HAW/BT7/Room/481/A/Temp"
#endif

static void _resp_handler(unsigned req_state, coap_pkt_t* pdu, sock_udp_ep_t *remote);
static ssize_t _payload_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx);

static const coap_resource_t _resources[] = {
    { URI "/0000", COAP_GET, _payload_handler, NULL },
};

static gcoap_listener_t _listener = {
    &_resources[0],
    sizeof(_resources) / sizeof(_resources[0]),
    NULL
};

static ssize_t _payload_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    char payload[4];
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    memcpy(pdu->payload, payload, sizeof(payload));
    return gcoap_finish(pdu, sizeof(payload), COAP_FORMAT_TEXT);
}

static void _resp_handler(unsigned req_state, coap_pkt_t* pdu,
                          sock_udp_ep_t *remote)
{
    (void)remote;       /* not interested in the source currently */

    if (req_state == GCOAP_MEMO_TIMEOUT) {
        printf("gcoap: timeout for msg ID %02u\n", coap_get_id(pdu));
        return;
    }
    else if (req_state == GCOAP_MEMO_ERR) {
        printf("gcoap: error in response\n");
        return;
    }
}

void gcoap_send(void)
{
    uint8_t buf[GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;

    int code_pos = 0;

    unsigned msg_type = COAP_TYPE_NON;
    //msg_type = COAP_TYPE_CON;

    gcoap_req_init(&pdu, &buf[0], GCOAP_PDU_BUF_SIZE, code_pos+1, URI "/0000");
    coap_hdr_set_type(pdu.hdr, msg_type);
    len = gcoap_finish(&pdu, 0, COAP_FORMAT_NONE);

    sock_udp_ep_t remote;

    remote.family = AF_INET6;
    int iface = 7;
    remote.netif = iface;
    remote.port = 5683;
    memcpy(&remote.addr.ipv6[0], &dst_ipv6_addr.u8[0], sizeof(dst_ipv6_addr.u8));

    gcoap_req_send2(buf, len, &remote, _resp_handler);
}

static int _start_exp(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    for (unsigned i = 0; i < MAX_REQS; i++) {
        printf("i;%u;%s\n", i, URI "/0000");
        gcoap_send();
        xtimer_usleep(DELAY);
    }

    return 0;
}

static const shell_command_t shell_commands[] = {
    { "start", "start consumer", _start_exp },
    { NULL, NULL, NULL }
};

int main(void)
{
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    gcoap_register_listener(&_listener);

#if defined (NODE_CONSUMER) || defined (NODE_PRODUCER)
    uint8_t l2addr[GNRC_IPV6_NIB_L2ADDR_MAX_LEN];
    size_t l2addr_len = 0;
#ifdef NODE_CONSUMER
    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7b64:1e7d:4a9b:bd22");
    l2addr_len = gnrc_netif_addr_from_str("BD:22", l2addr);
#elif NODE_PRODUCER
    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7b62:1b6d:89cc:89ca");
    l2addr_len = gnrc_netif_addr_from_str("89:CA", l2addr);
#endif
    gnrc_ipv6_nib_nc_set(&dst_ipv6_addr, 7, l2addr, l2addr_len);
#endif

#ifdef NODE_CONSUMER
#endif

    /* start shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should never be reached */
    return 0;
}
