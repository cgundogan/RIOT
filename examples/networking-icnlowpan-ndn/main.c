#include <stdio.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "ccn-lite-riot.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pktdump.h"

#include "periph/gpio.h"

#include "ccnl-pkt-builder.h"
#include "ccnl-producer.h"

#include "ccnl-pkt-ndntlv.h"
#include "net/netstats.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (15 * 1024 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

#ifndef INTBUFSIZE
#define INTBUFSIZE (256)
#endif

#ifndef MAX_REQS
#define MAX_REQS (10000U)
#endif

#ifndef DELAY
#define DELAY (100U * 1000U)
#endif

#ifndef ICNL_URI
#define ICNL_URI "/HAW/BT7/Room/481/A/Temp"
#endif

#ifndef ICNL_PREFIX
#define ICNL_PREFIX "/HAW"
#endif

#ifndef NETWORKING_VERBOSE
#define NETWORKING_VERBOSE (1)
#endif

#ifndef NETWORKING_ENERGY
#define NETWORKING_ENERGY (0)
#endif

static netstats_t *stats;

static unsigned payload_len = 0;

static unsigned char _int_buf[INTBUFSIZE];

uint32_t networking_send_lowpan = 0;
uint32_t networking_send_netif1 = 0;
uint32_t networking_send_netif2 = 0;
uint32_t networking_send_netifdelta = 0;
uint32_t networking_send_net = 0;
uint32_t networking_send_app = 0;

uint32_t networking_content_creation_diff = 0;

uint32_t networking_recv_lowpan = 0;
uint32_t networking_recv_app = 0;
uint32_t networking_recv_net = 0;
uint32_t networking_recv_netif = 0;
uint32_t networking_recv_netif1 = 0;
uint32_t networking_recv_netif2 = 0;
uint32_t networking_recv_netifdelta = 0;

bool networking_recv_netiffirst = true;
uint32_t networking_msg_type = 1; // true=Req, false=Resp

bool first_tx = true;

static char payload[256];

int producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from, struct ccnl_pkt_s *pkt)
{
    (void) relay;
    (void) from;
    (void) pkt;
    (void) payload;
    (void) networking_content_creation_diff;

    networking_send_app = xtimer_now_usec();
#if NETWORKING_ENERGY
#ifdef NODE_PRODUCER
        gpio_set(NETWORKING_PRODUCER_APP_RX_PIN);
        gpio_clear(NETWORKING_PRODUCER_APP_RX_PIN);
#endif
#ifdef NODE_FORWARDER
        gpio_set(NETWORKING_FORWARDER_APP_RX_PIN);
        gpio_clear(NETWORKING_FORWARDER_APP_RX_PIN);
#endif
#endif
#if defined(NODE_PRODUCER)
    networking_content_creation_diff = networking_send_app;
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    struct ccnl_content_s *c = ccnl_mkContentObject(pkt->pfx, (unsigned char*) payload, payload_len, NULL);
    ccnl_content_add2cache(relay, c);
    networking_content_creation_diff = xtimer_now_usec() - networking_content_creation_diff;
#endif

    return 0;
}

static int _enable_local_p(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    payload_len = atoi(argv[1]);

    ccnl_set_local_producer(producer_func);

    return 0;
}

void start_exp(void)
{
    memset(_int_buf, '\0', INTBUFSIZE);

    for (unsigned i = 0; i < MAX_REQS; i++) {
#if NETWORKING_ENERGY
#ifdef NODE_CONSUMER
        gpio_set(NETWORKING_CONSUMER_APP_TX_PIN);
        gpio_clear(NETWORKING_CONSUMER_APP_TX_PIN);
#endif
#endif
        networking_send_app = xtimer_now_usec();

        static char s[CCNL_MAX_PREFIX_SIZE];
        memset(s, '\0', CCNL_MAX_PREFIX_SIZE);

        snprintf (s, CCNL_MAX_PREFIX_SIZE, ICNL_URI "/%04u", i);

        //printf("i;%u;%s\n", i, s);

        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(s, CCNL_SUITE_NDNTLV, NULL);
        ccnl_send_interest(prefix, _int_buf, INTBUFSIZE, NULL);
        //printf("t;%lu;%lu;%lu;%lu\n", networking_send_app, networking_send_net, networking_send_netif2, networking_send_netifdelta);
        //networking_send_netifdelta = 0;
        ccnl_prefix_free(prefix);
        xtimer_usleep(DELAY);
    }

    /*
    printf("s;%u;%u;%u;%u;%u;%u;%u\n",
           (unsigned) stats->rx_count,
           (unsigned) stats->rx_bytes,
           (unsigned) (stats->tx_unicast_count + stats->tx_mcast_count),
           (unsigned) stats->tx_mcast_count,
           (unsigned) stats->tx_bytes,
           (unsigned) stats->tx_success,
           (unsigned) stats->tx_failed);
   */

#if NETWORKING_VERBOSE
    puts("exp_done");
#endif
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

static int _start_exp(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    start_exp();

    return 0;
}

static const shell_command_t shell_commands[] = {
    { "sp", "start producer", _enable_local_p },
    { "start", "start consumer", _start_exp },
    { "stats", "get stats", _get_stats },
    { NULL, NULL, NULL },
};

int main(void)
{
    tlsf_add_global_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("experiment_started");

    ccnl_core_init();

    ccnl_start();

    /* get the default interface */
    gnrc_netif_t *netif;

    /* set the relay's PID, configure the interface to use CCN nettype */
    if (((netif = gnrc_netif_iter(NULL)) == NULL) ||
        (ccnl_open_netif(netif->pid, GNRC_NETTYPE_CCN) < 0)) {
        puts("Error registering at network interface!");
        return -1;
    }

    uint16_t src_len = 8U;
    gnrc_netapi_set(netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
    //gnrc_netapi_get(hopp_netif->pid, NETOPT_ADDRESS_LONG, 0, hwaddr, sizeof(hwaddr));

#ifdef MODULE_GNRC_ICNLOWPAN_HC
    gnrc_nettype_t netreg_type = GNRC_NETTYPE_SIXLOWPAN;
    gnrc_netapi_set(netif->pid, NETOPT_PROTO, 0, &netreg_type, sizeof(gnrc_nettype_t));
#endif

    netopt_enable_t opt = NETOPT_ENABLE;
    gnrc_netapi_set(netif->pid, NETOPT_TX_START_IRQ, 0, &opt, sizeof(opt));

    gnrc_netapi_get(netif->pid, NETOPT_STATS, NETSTATS_LAYER2, &stats, sizeof(&stats));

#ifdef MODULE_PKTDUMP
    gnrc_netreg_entry_t dump = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                          gnrc_pktdump_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &dump);
#endif

    char defpfxs[CCNL_MAX_PREFIX_SIZE] = ICNL_PREFIX;
    struct ccnl_prefix_s *defpfx = ccnl_URItoPrefix(defpfxs, CCNL_SUITE_NDNTLV, NULL);
    (void) defpfx;


#if defined(NODE_CONSUMER) || defined(NODE_FORWARDER)
#if defined(NODE_CONSUMER) && (MULTIHOP)
    uint8_t relay_addr[] = { 0x79, 0x64, 0x0C, 0x7D, 0x9F, 0x31, 0x02, 0xEE };
#elif defined(NODE_CONSUMER)
    uint8_t relay_addr[] = { 0x79, 0x64, 0x1E, 0x7D, 0x4A, 0x9B, 0xBD, 0x22 };
#endif
#ifdef NODE_FORWARDER
    uint8_t relay_addr[] = { 0x79, 0x64, 0x1E, 0x7D, 0x4A, 0x9B, 0xBD, 0x22 };
#endif
    //uint8_t relay_addr[] = { 0xBD, 0x22 };

    sockunion sun;
    sun.sa.sa_family = AF_PACKET;
    memcpy(&(sun.linklayer.sll_addr), relay_addr, sizeof(relay_addr));
    sun.linklayer.sll_halen = sizeof(relay_addr);
    sun.linklayer.sll_protocol = htons(ETHERTYPE_NDN);


    struct ccnl_face_s *fibface = ccnl_get_face_or_create(&ccnl_relay, 0, &sun.sa, sizeof(sun.linklayer));
    fibface->flags |= CCNL_FACE_FLAGS_STATIC;

    if (ccnl_fib_add_entry(&ccnl_relay, defpfx, fibface) != 0) {
        printf("Error adding to the FIB\n");
        return -1;
    }
#endif

#ifdef NODE_PRODUCER
    payload_len = 4;
    ccnl_set_local_producer(producer_func);
#endif
#ifdef NODE_FORWARDER
    payload_len = 0;
    ccnl_set_local_producer(producer_func);
#endif

#if NETWORKING_ENERGY
#ifdef NODE_CONSUMER
    gpio_init(NETWORKING_CONSUMER_APP_TX_PIN, GPIO_OUT);
    gpio_init(NETWORKING_CONSUMER_RADIO_TX_DONE_PIN, GPIO_OUT);
    gpio_init(NETWORKING_CONSUMER_APP_RX_PIN, GPIO_OUT);
    gpio_clear(NETWORKING_CONSUMER_APP_TX_PIN);
    gpio_clear(NETWORKING_CONSUMER_RADIO_TX_DONE_PIN);
    gpio_clear(NETWORKING_CONSUMER_APP_RX_PIN);

    gpio_init(NETWORKING_CONSUMER_TX_START_PIN, GPIO_OUT);
    gpio_clear(NETWORKING_CONSUMER_TX_START_PIN);
#endif
#ifdef NODE_PRODUCER
    gpio_init(NETWORKING_PRODUCER_TX_START_PIN, GPIO_OUT);
    gpio_clear(NETWORKING_PRODUCER_TX_START_PIN);

    gpio_init(NETWORKING_PRODUCER_APP_RX_PIN, GPIO_OUT);
    gpio_init(NETWORKING_PRODUCER_RADIO_RX_DONE_PIN, GPIO_OUT);
    gpio_init(NETWORKING_PRODUCER_RADIO_TX_DONE_PIN, GPIO_OUT);
    gpio_clear(NETWORKING_PRODUCER_APP_RX_PIN);
    gpio_clear(NETWORKING_PRODUCER_RADIO_RX_DONE_PIN);
    gpio_clear(NETWORKING_PRODUCER_RADIO_TX_DONE_PIN);
#endif
#ifdef NODE_FORWARDER
    gpio_init(NETWORKING_FORWARDER_APP_RX_PIN, GPIO_OUT);
    gpio_init(NETWORKING_FORWARDER_RADIO_RX_DONE_PIN, GPIO_OUT);
    gpio_init(NETWORKING_FORWARDER_RADIO_TX_DONE_PIN, GPIO_OUT);
    gpio_clear(NETWORKING_FORWARDER_APP_RX_PIN);
    gpio_clear(NETWORKING_FORWARDER_RADIO_RX_DONE_PIN);
    gpio_clear(NETWORKING_FORWARDER_RADIO_TX_DONE_PIN);
#endif
#endif

#if NETWORKING_ENERGY
#ifdef NODE_CONSUMER
    xtimer_usleep(10 * 1000 * 1000);
    start_exp();
#endif
#endif

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
