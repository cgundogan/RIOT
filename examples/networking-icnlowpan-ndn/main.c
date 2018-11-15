#include <stdio.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "ccn-lite-riot.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pktdump.h"

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

#ifndef URI
#define URI "/HAW/BT7/Room/481/A/Temp"
#endif

static netstats_t *stats;

static unsigned char _int_buf[INTBUFSIZE];

int producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from, struct ccnl_pkt_s *pkt)
{
    (void) from;
    static const char payload[4];

    char s[CCNL_MAX_PREFIX_SIZE];

    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("d;%s\n", s);
    struct ccnl_content_s *c = ccnl_mkContentObject(pkt->pfx, (unsigned char*) payload, sizeof(payload)/sizeof(payload[0]), NULL);
    ccnl_content_add2cache(relay, c);

    if (!memcmp(pkt->pfx->comp[6], "9999", strlen("9999"))) {
        printf("s;%u;%u;%u;%u;%u;%u;%u\n",
               (unsigned) stats->rx_count,
               (unsigned) stats->rx_bytes,
               (unsigned) (stats->tx_unicast_count + stats->tx_mcast_count),
               (unsigned) stats->tx_mcast_count,
               (unsigned) stats->tx_bytes,
               (unsigned) stats->tx_success,
               (unsigned) stats->tx_failed);
    }

    return 0;
}

static int _enable_local_p(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    ccnl_set_local_producer(producer_func);

    return 0;
}

static int _start_exp(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    memset(_int_buf, '\0', INTBUFSIZE);

    for (unsigned i = 0; i < MAX_REQS; i++) {
        char s[CCNL_MAX_PREFIX_SIZE] = URI;
        snprintf (s, CCNL_MAX_PREFIX_SIZE, URI "/%04u", i);

        printf("i;%u;%s\n", i, s);

        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(s, CCNL_SUITE_NDNTLV, NULL);
        ccnl_send_interest(prefix, _int_buf, INTBUFSIZE, NULL);
        ccnl_prefix_free(prefix);
        xtimer_usleep(DELAY);
    }

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
    { NULL, NULL, NULL },
};

int main(void)
{
    tlsf_add_global_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Basic CCN-Lite example");

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

    uint16_t src_len = 8;
    gnrc_netapi_set(netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));

#ifdef MODULE_GNRC_ICNLOWPAN_HC
    gnrc_nettype_t netreg_type = GNRC_NETTYPE_SIXLOWPAN;
    gnrc_netapi_set(netif->pid, NETOPT_PROTO, 0, &netreg_type, sizeof(gnrc_nettype_t));
#endif

    gnrc_netapi_get(netif->pid, NETOPT_STATS, NETSTATS_LAYER2, &stats, sizeof(&stats));

#ifdef MODULE_PKTDUMP
    gnrc_netreg_entry_t dump = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                          gnrc_pktdump_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &dump);
#endif

    char defpfxs[CCNL_MAX_PREFIX_SIZE] = "/HAW";
    struct ccnl_prefix_s *defpfx = ccnl_URItoPrefix(defpfxs, CCNL_SUITE_NDNTLV, NULL);
    (void) defpfx;


    //uint8_t relay_addr[] = { 0x79, 0x64, 0x1E, 0x7D, 0x4A, 0x9B, 0xBD, 0x22 };
    uint8_t relay_addr[] = { 0xBD, 0x22 };

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

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
