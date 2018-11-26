#include <stdio.h>
#include "msg.h"

#include "net/gcoap.h"
#include "kernel_types.h"
#include "shell.h"
#include "net/gnrc/ipv6/nib.h"

#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#if defined (NODE_CONSUMER) || defined (NODE_PRODUCER) || defined (NODE_FORWARDER)
uint8_t networking_src_l2addr[GNRC_IPV6_NIB_L2ADDR_MAX_LEN];
uint8_t networking_dst_l2addr[GNRC_IPV6_NIB_L2ADDR_MAX_LEN];
static ipv6_addr_t src_ipv6_addr;
static ipv6_addr_t dst_ipv6_addr;
static ipv6_addr_t pfx, nexthop;
#endif

#ifndef MAX_REQS
#define MAX_REQS (1000U)
#endif

#ifndef DELAY
#define DELAY (100U * 1000U)
#endif

#ifndef ICNL_URI
#define ICNL_URI "/HAW/BT7/Room/481/A/Temp"
#endif

#ifndef NETWORKING_VERBOSE
#define NETWORKING_VERBOSE (1)
#endif

static netstats_t *stats;

uint32_t networking_send_netif1 = 0;
uint32_t networking_send_netif2 = 0;
uint32_t networking_send_netifdelta = 0;
uint32_t networking_send_net = 0;
uint32_t networking_send_app = 0;
uint32_t networking_send_lowpan = 0;

uint32_t networking_recv_lowpan = 0;
uint32_t networking_recv_app = 0;
uint32_t networking_recv_net = 0;
uint32_t networking_recv_netif = 0;
uint32_t networking_recv_netif1 = 0;
uint32_t networking_recv_netif2 = 0;
uint32_t networking_recv_netifdelta = 0;

bool networking_recv_netiffirst = true;
uint32_t networking_msg_type = 1; // true=Interest, false=Data

static void _resp_handler(unsigned req_state, coap_pkt_t* pdu, sock_udp_ep_t *remote);
static ssize_t _payload_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx);

static unsigned payload_len = 0;
static char payload[256];

static const coap_resource_t _resources[] = {
    { ICNL_URI "/0000", COAP_GET, _payload_handler, NULL },
};

static gcoap_listener_t _listener = {
    &_resources[0],
    sizeof(_resources) / sizeof(_resources[0]),
    NULL
};

static ssize_t _payload_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    memcpy(pdu->payload, payload, payload_len);
    ssize_t tmp=gcoap_finish(pdu, payload_len, COAP_FORMAT_TEXT);
    networking_send_app = xtimer_now_usec();
    return tmp;
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
    networking_recv_app = xtimer_now_usec();
#ifdef NODE_CONSUMER
#if NETWORKING_VERBOSE
    printf("rx;%lu;%lu;%lu;%lu;%lu;0\n", networking_recv_app, networking_recv_net, networking_recv_netif, networking_recv_netifdelta, networking_recv_lowpan);
    networking_recv_netifdelta = 0;
    networking_recv_netiffirst = true;
#endif
#endif
}

void gcoap_send(void)
{
    uint8_t buf[GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;

    int code_pos = 0;

    unsigned msg_type = COAP_TYPE_NON;
    //msg_type = COAP_TYPE_CON;

    gcoap_req_init(&pdu, &buf[0], GCOAP_PDU_BUF_SIZE, code_pos+1, ICNL_URI "/0000");
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

    ipv6_addr_from_str(&dst_ipv6_addr, "2001:db8::2");

    for (unsigned i = 0; i < MAX_REQS; i++) {
        networking_send_app = xtimer_now_usec();
        //printf("i;%u;%s\n", i, ICNL_URI "/0000");
        gcoap_send();
        xtimer_usleep(DELAY);
    }

    puts("exp_done");

    return 0;
}

static int _enable_local_p(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    payload_len = atoi(argv[1]);

    return 0;
}

static int _get_stats(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    printf("s;%u;%u;%u;%u;%u;%u;%u\n",
           (unsigned) stats->rx_count,
           (unsigned) stats->rx_bytes,
           (unsigned) (stats->tx_unicast_count + stats->tx_mcast_count),
           (unsigned) stats->tx_mcast_count,
           (unsigned) stats->tx_bytes,
           (unsigned) stats->tx_success,
           (unsigned) stats->tx_failed);
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "sp", "start producer", _enable_local_p },
    { "start", "start consumer", _start_exp },
    { "stats", "get stats", _get_stats },
    { NULL, NULL, NULL }
};

int main(void)
{
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    gcoap_register_listener(&_listener);

#if defined (NODE_CONSUMER) || defined (NODE_PRODUCER) || defined (NODE_FORWARDER)
    uint8_t l2addr[GNRC_IPV6_NIB_L2ADDR_MAX_LEN];
    (void) l2addr;
    size_t l2addr_len = 0;
    (void) src_ipv6_addr;
    (void) pfx;
#if defined (NODE_FORWARDER)
    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7b64:1e7d:4a9b:bd22");
    l2addr_len = gnrc_netif_addr_from_str("79:64:1E:7D:4A:9B:BD:22", networking_dst_l2addr);
    gnrc_ipv6_nib_nc_set(&dst_ipv6_addr, 7, networking_dst_l2addr, l2addr_len);
    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7b62:1b6d:89cc:89ca");
    l2addr_len = gnrc_netif_addr_from_str("79:62:1B:6D:89:CC:89:CA", networking_src_l2addr);
    gnrc_ipv6_nib_nc_set(&dst_ipv6_addr, 7, networking_src_l2addr, l2addr_len);

    ipv6_addr_from_str(&src_ipv6_addr, "2001:db8::1");
    ipv6_addr_from_str(&nexthop, "fe80::7b62:1b6d:89cc:89ca");
    gnrc_ipv6_nib_ft_add(&src_ipv6_addr, 128, &nexthop, 7, 0);
    ipv6_addr_from_str(&dst_ipv6_addr, "2001:db8::2");
    ipv6_addr_from_str(&nexthop, "fe80::7b64:1e7d:4a9b:bd22");
    gnrc_ipv6_nib_ft_add(&dst_ipv6_addr, 128, &nexthop, 7, 0);
#endif
#if defined (NODE_CONSUMER)
    ipv6_addr_from_str(&src_ipv6_addr, "2001:db8::1");
    gnrc_netapi_set(7, NETOPT_IPV6_ADDR, 128 << 8U, &src_ipv6_addr, sizeof(src_ipv6_addr));

    ipv6_addr_from_str(&pfx, "2001:db8::2");
#if MULTIHOP
    ipv6_addr_from_str(&nexthop, "fe80::7b64:c7d:9f31:2ee");
    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7b64:c7d:9f31:2ee");
    l2addr_len = gnrc_netif_addr_from_str("79:64:0C:7D:9F:31:02:EE", l2addr);
#else
    ipv6_addr_from_str(&nexthop, "fe80::7b64:1e7d:4a9b:bd22");
    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7b64:1e7d:4a9b:bd22");
    l2addr_len = gnrc_netif_addr_from_str("79:64:1E:7D:4A:9B:BD:22", l2addr);
#endif
    gnrc_ipv6_nib_nc_set(&dst_ipv6_addr, 7, l2addr, l2addr_len);
    gnrc_ipv6_nib_ft_add(&pfx, 128, &nexthop, 7, 0);
#endif
#if defined (NODE_PRODUCER)
    ipv6_addr_from_str(&src_ipv6_addr, "2001:db8::2");
    gnrc_netapi_set(7, NETOPT_IPV6_ADDR, 128 << 8U, &src_ipv6_addr, sizeof(src_ipv6_addr));

    ipv6_addr_from_str(&pfx, "2001:db8::1");
#if MULTIHOP
    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7b64:c7d:9f31:2ee");
    l2addr_len = gnrc_netif_addr_from_str("79:64:0C:7D:9F:31:02:EE", l2addr);
    ipv6_addr_from_str(&nexthop, "fe80::7b64:c7d:9f31:2ee");
#else
    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7b62:1b6d:89cc:89ca");
    l2addr_len = gnrc_netif_addr_from_str("79:62:1B:6D:89:CC:89:CA", l2addr);
    ipv6_addr_from_str(&nexthop, "fe80::7b62:1b6d:89cc:89ca");
#endif
    gnrc_ipv6_nib_nc_set(&dst_ipv6_addr, 7, l2addr, l2addr_len);
    gnrc_ipv6_nib_ft_add(&pfx, 128, &nexthop, 7, 0);
#endif
#endif

    gnrc_netif_t *netif;
    netif = gnrc_netif_iter(NULL);
    uint16_t src_len = 8U;
    gnrc_netapi_set(netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
    gnrc_netapi_get(netif->pid, NETOPT_STATS, NETSTATS_LAYER2, &stats, sizeof(&stats));

    netopt_enable_t opt = NETOPT_ENABLE;
    gnrc_netapi_set(netif->pid, NETOPT_TX_START_IRQ, 0, &opt, sizeof(opt));

    /* start shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should never be reached */
    return 0;
}
