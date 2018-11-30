#include <stdio.h>
#include "msg.h"

#include "kernel_types.h"
#include "shell.h"
#include "random.h"
#include "net/gnrc/ipv6/nib.h"
#include "net/gnrc/udp.h"
#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/hdr.h"

#define MAIN_QUEUE_SIZE (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

uint8_t networking_dst_l2addr[GNRC_IPV6_NIB_L2ADDR_MAX_LEN];
static ipv6_addr_t dst_ipv6_addr;
static ipv6_addr_t nexthop;

static gnrc_netif_t *netif;

#ifndef DELAY_MIN
#define DELAY_MIN (500U * 1000U)
#endif
#ifndef DELAY_MAX
#define DELAY_MAX (2U * 500U * 1000U)
#endif
#ifndef DELAY_BURST
#define DELAY_BURST (random_uint32_range(2,6))
#endif
#ifndef BURST_COUNT
#define BURST_COUNT (100U)
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

bool first_tx = true;
static void send(void)
{
    static const uint16_t port = 8888;
    static const size_t data_len = 60;

	gnrc_pktsnip_t *payload, *udp, *ip;
	payload = gnrc_pktbuf_add(NULL, NULL, data_len, GNRC_NETTYPE_UNDEF);
	memset(payload->data, 0, data_len);
	udp = gnrc_udp_hdr_build(payload, port, port);
	ip = gnrc_ipv6_hdr_build(udp, NULL, &dst_ipv6_addr);
	gnrc_pktsnip_t *netiff = gnrc_netif_hdr_build(NULL, 0, NULL, 0);
	((gnrc_netif_hdr_t *)netiff->data)->if_pid = (kernel_pid_t)netif->pid;
	LL_PREPEND(ip, netiff);
	gnrc_netapi_dispatch_send(GNRC_NETTYPE_UDP, GNRC_NETREG_DEMUX_CTX_ALL, ip);
}

static int _start_exp(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    ipv6_addr_from_str(&dst_ipv6_addr, "2001:db7::1");

    while (1) {
		for (unsigned i = 0; i < BURST_COUNT; ++i) {
			send();
			xtimer_usleep(DELAY_BURST);
		}
        xtimer_usleep(random_uint32_range(DELAY_MIN, DELAY_MAX));
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

    size_t l2addr_len = 0;

    netif = gnrc_netif_iter(NULL);

    ipv6_addr_from_str(&dst_ipv6_addr, "fe80::7baa:1eaa:4aaa:bdaa");
    l2addr_len = gnrc_netif_addr_from_str("79:aa:1E:aa:4A:aa:BD:aa", networking_dst_l2addr);
    gnrc_ipv6_nib_nc_set(&dst_ipv6_addr, netif->pid, networking_dst_l2addr, l2addr_len);

    ipv6_addr_from_str(&dst_ipv6_addr, "2001:db7::1");
    ipv6_addr_from_str(&nexthop, "fe80::7baa:1eaa:4aaa:bdaa");
    gnrc_ipv6_nib_ft_add(&dst_ipv6_addr, 128, &nexthop, netif->pid, 0);

    uint16_t src_len = 8U;
    gnrc_netapi_set(netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));

    gnrc_netapi_get(netif->pid, NETOPT_STATS, NETSTATS_LAYER2, &stats, sizeof(&stats));

    uint8_t retrans = 0U;
    gnrc_netapi_set(netif->pid, NETOPT_RETRANS, 0, &retrans, sizeof(retrans));

    netopt_enable_t opt = NETOPT_DISABLE;
    gnrc_netapi_set(netif->pid, NETOPT_CSMA, 0, &opt, sizeof(opt));

    opt = NETOPT_DISABLE;
    gnrc_netapi_set(netif->pid, NETOPT_ACK_REQ, 0, &opt, sizeof(opt));

    _start_exp(0, NULL);

    /* start shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should never be reached */
    return 0;
}
