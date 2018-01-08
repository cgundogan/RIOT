/*
 * Copyright (C) 2017 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdio.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "ccn-lite-riot.h"
#include "ccnl-pkt-builder.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/netapi.h"

#include "thread.h"
#include "xtimer.h"
#include "random.h"

#include "compas/routing/dodag.h"
#include "compas/routing/nam.h"
#include "compas/routing/pam.h"
#include "compas/routing/sol.h"
#include "compas/trickle.h"

#include "evtimer.h"
#include "evtimer_msg.h"

#define MAIN_QSZ (4)
static msg_t _main_q[MAIN_QSZ];

uint8_t hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
#ifdef NOPUBSUB
#ifdef BOARD_NATIVE
char root_str[GNRC_NETIF_L2ADDR_MAXLEN * 3] = "ca:50:db:84:82:e7";
#else
char root_str[GNRC_NETIF_L2ADDR_MAXLEN * 3] = "15:11:6b:10:65:fb:bc:32";
#endif
#endif
char parent_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
char src_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];

#define TLSF_BUFFER     ((40 * 1024) / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

#define PUBSUB_STACKSZ (THREAD_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF + 1024)
static char pubsub_stack[PUBSUB_STACKSZ];
static kernel_pid_t pubsub_pid;
#define PUBSUB_QSZ  (64)
static msg_t _pubsub_q[PUBSUB_QSZ];
static gnrc_netif_t *pubsub_netif;
static struct ccnl_face_s *loopback_face;
#define CCNL_ENC_PUBSUB                 (0x08)
#define PUBSUB_SOL_PERIOD_BASE          (4 * US_PER_SEC)
#define PUBSUB_SOL_PERIOD_JITTER        (1 * US_PER_SEC)
#define PUBSUB_SOL_PERIOD               (PUBSUB_SOL_PERIOD_BASE + (random_uint32() % PUBSUB_SOL_PERIOD_JITTER))
#define PUBSUB_PARENT_TIMEOUT_PERIOD    ((300 + (random_uint32() % 120)) * US_PER_SEC)
#define PUBSUB_STALE_NAM_TIME           (10 * US_PER_SEC)
#define PUBSUB_SOL_MSG                  (0xBEF0)
#define PUBSUB_PAM_MSG                  (0xBEF1)
#define PUBSUB_NAM_MSG                  (0xBEF2)
#define PUBSUB_PARENT_TIMEOUT_MSG       (0xBFF3)
#define PUBSUB_NCACHE_DEL_MSG           (0xBFF4)
#define PUBSUB_REQ_MSG                  (0xBFF5)
#define PUBSUB_PUB_MSG                  (0xBFF6)
//#define PUBSUB_UNBLOCK_MSG              (0xBFF7)
#define PUBSUB_TX_NAM_ACK_MSG           (0xBFF7)
#define PUBSUB_PUB_AUTOMATED_MSG        (0xBFF8)
#define PUBSUB_NCACHE_REQUESTED_MSG     (0xBFF9)
#define TRICKLE_IMIN                    (512)
#define TRICKLE_IMAX                    (16)
#define TRICKLE_REDCONST                (10)
static msg_t pubsub_sol_msg = { .type = PUBSUB_SOL_MSG };
static xtimer_t pubsub_sol_timer;
static msg_t pubsub_pam_msg = { .type = PUBSUB_PAM_MSG };
static xtimer_t pubsub_pam_timer;
static xtimer_t pubsub_parent_timeout_timer;
static msg_t pubsub_parent_timeout_msg = { .type = PUBSUB_PARENT_TIMEOUT_MSG };

evtimer_msg_t evtimer;

#define PUBSUB_PUBLISH_TIMEOUT          (500 + (random_uint32() % 1000))
#define PUBSUB_INT_REQ_PERIOD           (100)
#define PUBSUB_INT_REQ_COUNT            (8)
#define PUBSUB_PUBLISH_TIME             ((random_uint32() % 30000))
#define PUBSUB_BLOCK_TIME               (8000)
#define PUBSUB_PUBLISH_NUMBERS          (1)
#define PUBSUB_MAX_PUBLISHES            (6)
#define PUBSUB_PUB_AUTOMATED_TIME       ((20 + (random_uint32() % 20)) * MS_PER_SEC)
evtimer_msg_event_t publish_reqs;
//evtimer_msg_event_t int_reqs[COMPAS_NAM_CACHE_LEN];
//evtimer_msg_event_t nam_dels[COMPAS_NAM_CACHE_LEN];
//static evtimer_msg_event_t publisher;
static evtimer_msg_event_t publisher_automated;
//static evtimer_msg_event_t blocker;
uint32_t nce_times[COMPAS_NAM_CACHE_LEN];
//uint8_t nce_req_count[COMPAS_NAM_CACHE_LEN];
//static bool publish = false;
static unsigned publish_numbers = 0;

compas_dodag_t dodag;

void pubsub_parent_timeout(compas_dodag_t *dodag)
{
    gnrc_netif_addr_to_str(dodag->parent.face.face_addr, dodag->parent.face.face_addr_len, parent_str);
    //printf("ps;to;%d;%s\n", dodag->rank, parent_str);
    dodag->parent.alive = false;
    xtimer_remove(&pubsub_sol_timer);
    xtimer_set_msg(&pubsub_sol_timer, PUBSUB_SOL_PERIOD, &pubsub_sol_msg, sched_active_pid);
    xtimer_remove(&pubsub_parent_timeout_timer);
}

bool pubsub_send(gnrc_pktsnip_t *pkt, uint8_t *addr, uint8_t addr_len)
{
    gnrc_pktsnip_t *hdr = gnrc_netif_hdr_build(NULL, 0, addr, addr_len);

    if (hdr == NULL) {
        puts("error: packet buffer full");
        gnrc_pktbuf_release(pkt);
        return false;
    }

    LL_PREPEND(pkt, hdr);

    if (!addr) {
        gnrc_netif_hdr_t *nethdr = (gnrc_netif_hdr_t *)hdr->data;
        nethdr->flags = GNRC_NETIF_HDR_FLAGS_BROADCAST;
    }

    if (gnrc_netapi_send(pubsub_netif->pid, pkt) < 1) {
        puts("error: unable to send");
        gnrc_pktbuf_release(pkt);
        return false;
    }
    return true;
}

void pubsub_send_sol(compas_dodag_t *dodag)
{
    //puts("TX SOL");
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, compas_sol_len() + 2, GNRC_NETTYPE_CCN);
    if (pkt == NULL) {
        puts("send_sol: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_PUBSUB;

    uint8_t *addr = NULL;
    size_t addr_len = 0;
    uint8_t flags = 0;


    if ((dodag->rank != COMPAS_DODAG_UNDEF) && (dodag->sol_num < 4)) {
        addr = dodag->parent.face.face_addr;
        addr_len = dodag->parent.face.face_addr_len;
        if (dodag->sol_num == 3) {
            dodag->flags |= COMPAS_DODAG_FLAGS_FLOATING;
            trickle_init(&dodag->trickle, TRICKLE_IMIN, TRICKLE_IMAX, TRICKLE_REDCONST);
            uint64_t trickle_int = trickle_next(&dodag->trickle);
            xtimer_remove(&pubsub_pam_timer);
            xtimer_set_msg64(&pubsub_pam_timer, trickle_int * MS_PER_SEC,
                             &pubsub_pam_msg, sched_active_pid);
        }
    }
    else {
        dodag->flags |= COMPAS_DODAG_FLAGS_FLOATING;
        if (dodag->rank != COMPAS_DODAG_UNDEF) {
            flags = COMPAS_SOL_FLAGS_TRICKLE;
        }
        if (dodag->parent.alive) {
            pubsub_parent_timeout(dodag);
            //puts("SOL: TIMEOUT");
        }
    }

    compas_sol_create((compas_sol_t *) (((uint8_t *) pkt->data) + 2), flags);
    pubsub_send(pkt, addr, addr_len);

    dodag->sol_num++;
}

void pubsub_send_nam(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    //puts("TX NAM");
    if (dodag->rank == COMPAS_DODAG_UNDEF) {
        puts("send_nam: not part of a DODAG");
        return;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, 2 + sizeof(compas_nam_t) +
                                          nce->name.name_len +
                                          sizeof(compas_tlv_t), GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("send_nam: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_PUBSUB;
    compas_nam_t *nam = (compas_nam_t *)(((uint8_t *) pkt->data) + 2);
    compas_nam_create(nam);
    compas_nam_tlv_add_name(nam, &nce->name);

    gnrc_netif_addr_to_str(dodag->parent.face.face_addr, dodag->parent.face.face_addr_len, parent_str);
    //printf("ps;pub;%d;%s;%.*s\n\n", dodag->rank, parent_str, nce->name.name_len, nce->name.name);
    printf("p;%d;%.*s;%s;%d\n", dodag->rank, nce->name.name_len, nce->name.name,parent_str,dodag->parent.alive);
    pubsub_send(pkt, dodag->parent.face.face_addr, dodag->parent.face.face_addr_len);
}

void pubsub_send_nam_ack(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    //puts("TX NAM");
    if (dodag->rank == COMPAS_DODAG_UNDEF) {
        puts("send_nam: not part of a DODAG");
        return;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, 2 + sizeof(compas_nam_t) +
                                          nce->name.name_len +
                                          sizeof(compas_tlv_t), GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("send_nam: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_PUBSUB;
    compas_nam_t *nam = (compas_nam_t *)(((uint8_t *) pkt->data) + 2);
    compas_nam_create(nam);
    compas_nam_tlv_add_name_ack(nam, &nce->name);

    gnrc_netif_addr_to_str(dodag->parent.face.face_addr, dodag->parent.face.face_addr_len, parent_str);
    printf("x;%d;%.*s;%s;%d\n", dodag->rank, nce->name.name_len, nce->name.name,parent_str,dodag->parent.alive);
    pubsub_send(pkt, nce->face.face_addr, nce->face.face_addr_len);
}

void pubsub_send_pam(compas_dodag_t *dodag, uint8_t *dst_addr, uint8_t dst_addr_len, bool redun)
{
    //puts("TX PAM");

    if (redun && (dodag->trickle.c >= dodag->trickle.k)) {
        return;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, compas_pam_len(dodag) + 2, GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("send_pam: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_PUBSUB;
    compas_pam_create(dodag, (compas_pam_t *) (((uint8_t *) pkt->data) + 2));
    pubsub_send(pkt, dst_addr, dst_addr_len);
}

void pubsub_publish(struct ccnl_relay_s *relay, compas_dodag_t *dodag, compas_nam_cache_entry_t *nce, uint32_t offset)
{
    (void) offset;

    bool found = false;
    for (struct ccnl_content_s *c = relay->contents; c; c = c->next) {
        char *spref = ccnl_prefix_to_path(c->pkt->pfx);
        //printf("COMPARE: %.*s;%s\n", nce->name.name_len, nce->name.name, spref);
        if (memcmp(nce->name.name, spref, strlen(spref)) == 0) {
            ccnl_free(spref);
            found = true;
            break;
        }
        ccnl_free(spref);
    }

    if (!found) {
        //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&publish_reqs[pos]);
        //printf("DELETE NAM: %.*s\n", nce->name.name_len, nce->name.name);
        //size_t pos = nce - dodag->nam_cache;
        //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&int_reqs[pos]);
        printf("d3;%d;%.*s;%d\n", dodag->rank, nce->name.name_len, nce->name.name, dodag->parent.alive);
        memset(nce, 0, sizeof(*nce));
        return;
    }

    if (dodag->parent.alive) {
        pubsub_send_nam(dodag, nce);
        //publish_reqs.msg.type = PUBSUB_NAM_MSG;
        //publish_reqs.msg.content.ptr = (void *) nce;
        //((evtimer_event_t *)&(publish_reqs[pos]))->offset = offset;
        //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&publish_reqs[pos]);
        //evtimer_add_msg(&evtimer, &publish_reqs[pos], pubsub_pid);
    }
}

bool pubsub_pub(char *pubname)
{
    compas_name_t name;
    compas_name_init(&name, pubname, strlen(pubname));
    compas_nam_cache_entry_t *nce = compas_nam_cache_add(&dodag, &name, NULL);
    if (nce) {
        char prefix_n[COMPAS_NAME_LEN + 1];
        memcpy(prefix_n, name.name, name.name_len);
        prefix_n[name.name_len] = '\0';
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(prefix_n, CCNL_SUITE_NDNTLV, NULL, NULL);
        struct ccnl_content_s *c = ccnl_mkContentObject(prefix, NULL, 0);
        ccnl_prefix_free(prefix);
        ccnl_content_add2cache(&ccnl_relay, c);
        nce->flags |= COMPAS_NAM_CACHE_FLAGS_REQUESTED;
        msg_t msg = { .type = PUBSUB_NAM_MSG, .content.value = 0x00 };
        msg_send(&msg, pubsub_pid);
        return true;
    }
    else {
        puts("NAM CACHE: NO SPACE");
    }
    return false;
}

void pubsub_handle_pam(struct ccnl_relay_s *relay, compas_dodag_t *dodag, compas_pam_t *pam,
                       uint8_t *src_addr, uint8_t src_addr_len, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    (void) dst_addr;
    (void) dst_addr_len;
    //puts("RX PAM");

    int state = compas_pam_parse(dodag, pam, src_addr, src_addr_len);
    //compas_dodag_print(dodag);

    if ((state == COMPAS_PAM_RET_CODE_CURRPARENT) ||
        (state == COMPAS_PAM_RET_CODE_NEWPARENT)  ||
        (state == COMPAS_PAM_RET_CODE_NONFLOATINGDODAG_WORSERANK)) {

        /*
        if ((state == COMPAS_PAM_RET_CODE_NEWPARENT) ||
            ((state == COMPAS_PAM_RET_CODE_CURRPARENT) && (dodag->sol_num > 3))) {
            trickle_init(&dodag->trickle, TRICKLE_IMIN, TRICKLE_IMAX, TRICKLE_REDCONST);
            uint64_t trickle_int = trickle_next(&dodag->trickle);
            xtimer_remove(&pubsub_pam_timer);
            xtimer_set_msg64(&pubsub_pam_timer, trickle_int * MS_PER_SEC,
                             &pubsub_pam_msg, sched_active_pid);
        }
        */

        char dodag_prfx[COMPAS_PREFIX_LEN + 1];
        memcpy(dodag_prfx, dodag->prefix.prefix, dodag->prefix.prefix_len);
        dodag_prfx[dodag->prefix.prefix_len] = '\0';
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(dodag_prfx, CCNL_SUITE_NDNTLV, NULL, NULL);

        if (state == COMPAS_PAM_RET_CODE_NEWPARENT) {
            gnrc_netif_addr_to_str(dodag->parent.face.face_addr, dodag->parent.face.face_addr_len, parent_str);
            printf("n;%d;%s\n", dodag->rank, parent_str);
            sockunion su;
            memset(&su, 0, sizeof(su));
            su.sa.sa_family = AF_PACKET;
            su.linklayer.sll_halen = src_addr_len;
            memcpy(su.linklayer.sll_addr, src_addr, src_addr_len);
            struct ccnl_face_s* from = ccnl_get_face_or_create(relay, 0, &(su.sa), sizeof(su.sa));

            from->flags |= CCNL_FACE_FLAGS_STATIC;
            ccnl_fib_rem_entry(relay, prefix, from);
            ccnl_fib_add_entry(relay, ccnl_prefix_dup(prefix), from);
        }

        if (!dodag->parent.alive) {
            gnrc_netif_addr_to_str(dodag->parent.face.face_addr, dodag->parent.face.face_addr_len, parent_str);
            printf("r;%d;%s\n", dodag->rank, parent_str);
            dodag->parent.alive = true;
            for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
                compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
                if (nce->in_use && compas_nam_cache_requested(nce->flags)) {
                    nce->retries = COMPAS_NAM_CACHE_RETRIES;
                }
            }
            msg_t msg = { .type = PUBSUB_NAM_MSG, .content.value = 0x00 };
            msg_send(&msg, pubsub_pid);
        }

        ccnl_prefix_free(prefix);

        dodag->sol_num = 0;
        xtimer_remove(&pubsub_sol_timer);

        xtimer_remove(&pubsub_parent_timeout_timer);
        xtimer_set_msg(&pubsub_parent_timeout_timer, PUBSUB_PARENT_TIMEOUT_PERIOD,
                       &pubsub_parent_timeout_msg, sched_active_pid);
        return;
    }
    else if ((state == COMPAS_PAM_RET_CODE_PARENT_WORSERANK) && dodag->parent.alive) {
        //printf("WORSE RANK PARENT\n");
        dodag->sol_num = 0xFF;
        pubsub_parent_timeout(dodag);
        pubsub_send_sol(dodag);
        return;
    }

    if (dodag->rank >= pam->rank) {
        trickle_increment_counter(&dodag->trickle);
    }

    /*
    if (!publish) {
        publish = true;
        publisher.msg.type = PUBSUB_PUB_MSG;
        ((evtimer_event_t *)&publisher)->offset = PUBSUB_PUBLISH_TIME;
        evtimer_add_msg(&evtimer, &publisher, pubsub_pid);
    }
    */

    return;
}

void pubsub_request(struct ccnl_relay_s *relay, compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    (void) dodag;
    char name[COMPAS_NAME_LEN + 1];
    memcpy(name, nce->name.name, nce->name.name_len);
    name[nce->name.name_len] = '\0';
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, NULL);
    sockunion su;
    memset(&su, 0, sizeof(su));
    su.sa.sa_family = AF_PACKET;
    su.linklayer.sll_halen = nce->face.face_addr_len;
    memcpy(su.linklayer.sll_addr, nce->face.face_addr, nce->face.face_addr_len);
    struct ccnl_face_s* to = ccnl_get_face_or_create(relay, 0, &(su.sa), sizeof(su.sa));
    ccnl_send_interest(prefix, NULL, 0, to);
    ccnl_prefix_free(prefix);
}

void pubsub_handle_nam(struct ccnl_relay_s *relay, compas_dodag_t *dodag, compas_nam_t *nam, uint8_t *src_addr, uint8_t src_addr_len, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    //puts("RX NAM");
    (void) dst_addr;
    (void) dst_addr_len;
    (void) relay;

    uint16_t offset = 0;
    compas_tlv_t *tlv = NULL;

    compas_face_t face;
    compas_face_init(&face, src_addr, src_addr_len);
    while(compas_nam_tlv_iter(nam, &offset, &tlv)) {
        if (tlv->type == COMPAS_TLV_NAME) {
            compas_name_t cname;
            compas_name_init(&cname, (const char *) (tlv + 1), tlv->length);

            char name[COMPAS_NAME_LEN + 1];
            memcpy(name, cname.name, cname.name_len);
            name[cname.name_len] = '\0';
            compas_nam_cache_entry_t *n = compas_nam_cache_find(dodag, &cname);
            if (!n) {
                n = compas_nam_cache_add(dodag, &cname, &face);
                if (!n) {
                    uint32_t now = xtimer_now_usec();
                    for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
                        compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
                        bool found = false;
                        for (struct ccnl_content_s *c = relay->contents; c; c = c->next) {
                            char *spref = ccnl_prefix_to_path(c->pkt->pfx);
                            if (memcmp(nce->name.name, spref, strlen(spref)) == 0) {
                                ccnl_free(spref);
                                found = true;
                                break;
                            }
                            ccnl_free(spref);
                        }
                        if (nce->in_use && (!compas_nam_cache_requested(nce->flags) || !found) && ((now - nce_times[nce - dodag->nam_cache]) > PUBSUB_STALE_NAM_TIME)) {
                            //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&publish_reqs[nce - dodag->nam_cache]);
                            //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&int_reqs[nce - dodag->nam_cache]);
                            //printf("DELETE NAM - MAKE ROOM: %.*s\n", nce->name.name_len, nce->name.name);
                            memset(nce, 0, sizeof(*nce));
                            n = compas_nam_cache_add(dodag, &cname, &face);
                            break;
                        }
                    }
                    if (!n) {
                        puts("NAM: NO SPACE LEFT");
                        continue;
                    }
                }
            }
            if (n) {
                for (struct ccnl_content_s *c = relay->contents; c; c = c->next) {
                    char *spref = ccnl_prefix_to_path(c->pkt->pfx);
                    if (memcmp(n->name.name, spref, strlen(spref)) == 0) {
                        ccnl_free(spref);
                        ccnl_content_remove(relay, c);
                        break;
                    }
                    ccnl_free(spref);
                }
                size_t pos = n - dodag->nam_cache;
                nce_times[pos] = xtimer_now_usec();
                msg_t msg;
                msg.type = PUBSUB_REQ_MSG;
                msg.content.ptr = n;
                msg_send(&msg, pubsub_pid);
                //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&int_reqs[pos]);
                //int_reqs[pos].msg.type = PUBSUB_REQ_MSG;
                //int_reqs[pos].msg.content.ptr = (void *) n;
                //((evtimer_event_t *)&(int_reqs[pos]))->offset = PUBSUB_INT_REQ_PERIOD;
                //evtimer_add_msg(&evtimer, &int_reqs[pos], pubsub_pid);
                //pubsub_request(relay, dodag, n);
            }
        }
        else if (tlv->type == COMPAS_TLV_NAME_ACK) {
            compas_name_t cname;
            compas_name_init(&cname, (const char *) (tlv + 1), tlv->length);
            compas_nam_cache_entry_t *n = compas_nam_cache_find(dodag, &cname);
            if (n && n->in_use) {
                msg_t msg;
                msg.type = PUBSUB_NCACHE_REQUESTED_MSG;
                msg.content.ptr = n;
                msg_send(&msg, pubsub_pid);
            }
        }
    }
    msg_t msg = { .type = PUBSUB_NAM_MSG, .content.value = 0x00 };
    msg_send(&msg, pubsub_pid);

    return;
}

void pubsub_handle_sol(compas_dodag_t *dodag, compas_sol_t *sol, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    //puts("RX SOL");
    if ((dodag->rank == COMPAS_DODAG_UNDEF) || (compas_dodag_floating(dodag->flags))) {
        return;
    }

    bool empty = false;
    for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
        compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
        if (!nce->in_use) {
            empty = true;
            break;
        }
    }

    if (!empty) {
        return;
    }

    if (compas_sol_reset_trickle(sol->flags)) {
        trickle_init(&dodag->trickle, TRICKLE_IMIN, TRICKLE_IMAX, TRICKLE_REDCONST);
        uint64_t trickle_int = trickle_next(&dodag->trickle);
        xtimer_remove(&pubsub_pam_timer);
        xtimer_set_msg64(&pubsub_pam_timer, trickle_int * MS_PER_SEC,
                         &pubsub_pam_msg, sched_active_pid);
    }
    else {
        pubsub_send_pam(dodag, dst_addr, dst_addr_len, false);
    }

    return;
}

int content_added(struct ccnl_relay_s *relay, struct ccnl_pkt_s *p)
{
    (void) relay;
    char *s = ccnl_prefix_to_path(p->pfx);

    compas_name_t cname;
    compas_name_init(&cname, s, strlen(s));
    compas_nam_cache_entry_t *n = compas_nam_cache_find(&dodag, &cname);
    msg_t msg;
    msg.type = PUBSUB_TX_NAM_ACK_MSG;
    msg.content.ptr = n;
    msg_send(&msg, pubsub_pid);

    if (n) {
        if (dodag.rank == COMPAS_DODAG_ROOT_RANK) {
            msg_t msg;
            msg.type = PUBSUB_NCACHE_DEL_MSG;
            msg.content.ptr = n;
            gnrc_netif_addr_to_str(dodag.parent.face.face_addr, dodag.parent.face.face_addr_len, parent_str);
            msg_send(&msg, pubsub_pid);
        }
        else {
            n->flags |= COMPAS_NAM_CACHE_FLAGS_REQUESTED;
            msg_t msg = { .type = PUBSUB_NAM_MSG, .content.value = 0x00 };
            msg_send(&msg, pubsub_pid);
        }
    }

    ccnl_free(s);
    return 1;
}

void pubsub_dispatcher(struct ccnl_relay_s *relay, compas_dodag_t *dodag, uint8_t *data, size_t data_len,
                       uint8_t *src_addr, uint8_t src_addr_len, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    (void) data_len;
    if (!((data[0] == 0x80) && (data[1] == 0x08))) {
        return;
    }
    switch (data[2]) {
        case COMPAS_MSG_TYPE_PAM:
            pubsub_handle_pam(relay, dodag, (compas_pam_t *) (data + 2), src_addr, src_addr_len, dst_addr, dst_addr_len);
            break;
        case COMPAS_MSG_TYPE_NAM:
            pubsub_handle_nam(relay, dodag, (compas_nam_t *) (data + 2), src_addr, src_addr_len, dst_addr, dst_addr_len);
            break;
        case COMPAS_MSG_TYPE_SOL:
            pubsub_handle_sol(dodag, (compas_sol_t *) (data + 2), src_addr, src_addr_len);
            break;
        default:
            break;
    }
}

int handle_int2(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                  struct ccnl_pkt_s *pkt) {
	(void) from;

    if (dodag.rank != COMPAS_DODAG_ROOT_RANK) {
        return 0;
    }

    if (pkt && pkt->pfx && pkt->pfx->compcnt) {
        if (!memcmp(pkt->pfx->comp[1], hwaddr_str, pkt->pfx->complen[1])) {
			struct ccnl_content_s *c = ccnl_mkContentObject(pkt->pfx, NULL, 0);
			if (c) {
				char *s = ccnl_prefix_to_path(c->pkt->pfx);
                printf("\na;%d;%s;%s;%d\n", dodag.rank, s, parent_str, dodag.parent.alive);
				ccnl_free(s);
				ccnl_content_add2cache(relay, c);
			}
		}
    }
    return 0;
}

int content_added2(struct ccnl_relay_s *relay, struct ccnl_pkt_s *p)
{
    (void) relay;
    char *s = ccnl_prefix_to_path(p->pfx);
	//struct ccnl_content_s *c = ccnl_content_new(&p);
	//if (c) {
		//ccnl_content_add2cache(relay, c);
        printf("\na;%d;%s;%s;%d\n", dodag.rank, s, parent_str, dodag.parent.alive);
	//}
    ccnl_free(s);
	return 1;
}

#if 0
int handle_int(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
               struct ccnl_pkt_s *pkt) {
    (void) relay;
    (void) from;
    compas_name_t cname;
    char *s = ccnl_prefix_to_path(pkt->pfx);
    compas_name_init(&cname, s, strlen(s));
    ccnl_free(s);
    compas_nam_cache_entry_t *n = compas_nam_cache_find(&dodag, &cname);

    if (n && compas_nam_cache_requested(n->flags)) {
        msg_t msg;
        msg.type = PUBSUB_NCACHE_REQUESTED_MSG;
        msg.content.ptr = n;
        msg_send(&msg, pubsub_pid);
        /*
        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&nam_dels[pos]);
        nam_dels[pos].msg.type = PUBSUB_NCACHE_DEL_MSG;
        nam_dels[pos].msg.content.ptr = (void *) n;
        ((evtimer_event_t *)&(nam_dels[pos]))->offset = 2000;
        evtimer_add_msg(&evtimer, &nam_dels[pos], pubsub_pid);
        */
    }
    return 0;
}
#endif

void *pubsub(void *arg)
{
    struct ccnl_relay_s *relay = (struct ccnl_relay_s *) arg;

    msg_init_queue(_pubsub_q, PUBSUB_QSZ);
    evtimer_init_msg(&evtimer);

    memset(&dodag, 0, sizeof(dodag));
    xtimer_set_msg(&pubsub_sol_timer, PUBSUB_SOL_PERIOD,
                   &pubsub_sol_msg, sched_active_pid);

    gnrc_netreg_entry_t _ne = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, sched_active_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_PUBSUB, &_ne);
    loopback_face = ccnl_get_face_or_create(&ccnl_relay, -1, NULL, 0);

#ifdef NOPUBSUB
    ccnl_set_local_producer(handle_int2);
    ccnl_set_callback_content_add(content_added2);
#else
    //ccnl_set_local_producer(handle_int);
    ccnl_set_callback_content_add(content_added);
#endif

    while (1) {
        msg_t msg;
        msg_receive(&msg);
        gnrc_pktsnip_t *pkt, *netif_snip;
        gnrc_netif_hdr_t *netif_hdr;
        compas_nam_cache_entry_t *nce;
        char pubname[COMPAS_NAME_LEN];
        bool res = true;

        switch (msg.type) {
            case PUBSUB_SOL_MSG:
                if ((dodag.rank != COMPAS_DODAG_ROOT_RANK) &&
                    (dodag.rank == COMPAS_DODAG_UNDEF || !dodag.parent.alive)) {
                    pubsub_send_sol(&dodag);
                    xtimer_set_msg(&pubsub_sol_timer, PUBSUB_SOL_PERIOD,
                                   &pubsub_sol_msg, sched_active_pid);
                }
                break;
            case PUBSUB_PAM_MSG:
                if (dodag.rank != COMPAS_DODAG_UNDEF) {
                    pubsub_send_pam(&dodag, NULL, 0, true);
                    uint64_t trickle_int = trickle_next(&dodag.trickle);
                    xtimer_set_msg64(&pubsub_pam_timer, trickle_int * MS_PER_SEC,
                                     &pubsub_pam_msg, sched_active_pid);
                }
                break;
            case PUBSUB_NAM_MSG:
                if ((dodag.rank != COMPAS_DODAG_UNDEF) && (dodag.parent.alive)) {
                    bool restart = false;
                    static size_t i = 0;
                    for (size_t j = 0; j < COMPAS_NAM_CACHE_LEN; j++) {
                        i = (i + 1) % COMPAS_NAM_CACHE_LEN;
                        compas_nam_cache_entry_t *nce = &dodag.nam_cache[i];
                        if (nce->in_use && compas_nam_cache_requested(nce->flags)) {
                            if (nce->retries > 0) {
                                restart = true;
                                nce->retries--;
                                pubsub_publish(relay, &dodag, nce, PUBSUB_PUBLISH_TIMEOUT);
                            }
                            else if ((nce->retries == 0) && (dodag.parent.alive)) {
                                /*
                                gnrc_netapi_set(pubsub_netif->pid, NETOPT_L2FILTER, 0, dodag.parent.face.face_addr, dodag.parent.face.face_addr_len);
                                blocker.msg.type = PUBSUB_UNBLOCK_MSG;
                                ((evtimer_event_t *)&publisher)->offset = PUBSUB_BLOCK_TIME;
                                evtimer_add_msg(&evtimer, &blocker, pubsub_pid);
                                */
                                dodag.sol_num = 0xFF;
                                pubsub_parent_timeout(&dodag);
                                pubsub_send_sol(&dodag);
                            }
                            break;
                        }
                    }
                    if (restart) {
                        evtimer_del(&evtimer, (evtimer_event_t *)&publish_reqs);
                        publish_reqs.msg.type = PUBSUB_NAM_MSG;
                        publish_reqs.msg.content.value = 0xFF;
                        ((evtimer_event_t *)&publish_reqs)->offset = PUBSUB_PUBLISH_TIMEOUT;
                        evtimer_add_msg(&evtimer, &publish_reqs, pubsub_pid);
                    }
                }
                break;
            case PUBSUB_REQ_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                if (nce->in_use) {
                    //printf("SEND INTEREST: %.*s\n", nce->name.name_len, nce->name.name);
                    pubsub_request(relay, &dodag, nce);
                }
                /*
                size_t pos = nce - dodag.nam_cache;
                if (nce->in_use && !compas_nam_cache_requested(nce->flags)) {
                    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&int_reqs[pos]);
                    if (nce_req_count[pos] < PUBSUB_INT_REQ_COUNT) {
                        gnrc_netif_addr_to_str(nce->face.face_addr, nce->face.face_addr_len, src_str);
                        printf("\nc;%d;%.*s;%s;%d;%d\n", dodag.rank, nce->name.name_len, nce->name.name, src_str, dodag.parent.alive, nce_req_count[pos]);
                        pubsub_request(relay, &dodag, nce);
                        int_reqs[pos].msg.type = PUBSUB_REQ_MSG;
                        int_reqs[pos].msg.content.ptr = (void *) nce;
                        nce_req_count[pos]++;
                        ((evtimer_event_t *)&(int_reqs[pos]))->offset = PUBSUB_INT_REQ_PERIOD;
                        evtimer_add_msg(&evtimer, &int_reqs[pos], pubsub_pid);
                    }
                    else {
                        printf("\nd4;%d;%.*s;%s;%d;%d\n", dodag.rank, nce->name.name_len, nce->name.name, src_str, dodag.parent.alive, nce_req_count[pos]);
                        memset(nce, 0, sizeof(*nce));
                    }
                }
                */
                break;
            case PUBSUB_PARENT_TIMEOUT_MSG:
                pubsub_parent_timeout(&dodag);
                break;
            case PUBSUB_NCACHE_DEL_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&publish_reqs);
                //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&int_reqs[nce - dodag.nam_cache]);
                //printf("DELETE NAM RECD INT: %.*s\n", nce->name.name_len, nce->name.name);
                //printf("\na;%d;%.*s;%s;%d\n", dodag.rank, nce->name.name_len, nce->name.name, parent_str, dodag.parent.alive);
                gnrc_netif_addr_to_str(dodag.parent.face.face_addr, dodag.parent.face.face_addr_len, parent_str);
                printf("a;%d;%.*s;%s;%d\n", dodag.rank, nce->name.name_len, nce->name.name, parent_str, dodag.parent.alive);
                for (struct ccnl_content_s *c = relay->contents; c; c = c->next) {
                    char *spref = ccnl_prefix_to_path(c->pkt->pfx);
                    if (memcmp(nce->name.name, spref, strlen(spref)) == 0) {
                        ccnl_free(spref);
                        ccnl_content_remove(relay, c);
                        break;
                    }
                    ccnl_free(spref);
                }
                memset(nce, 0, sizeof(*nce));
                break;
            case PUBSUB_NCACHE_REQUESTED_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                //evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&int_reqs[nce - dodag.nam_cache]);
                if (nce && nce->in_use) {
                    printf("d0;%d;%.*s;%d\n", dodag.rank, nce->name.name_len, nce->name.name, dodag.parent.alive);
                    memset(nce, 0, sizeof(*nce));
                    xtimer_remove(&pubsub_parent_timeout_timer);
                    xtimer_set_msg(&pubsub_parent_timeout_timer, PUBSUB_PARENT_TIMEOUT_PERIOD,
                                   &pubsub_parent_timeout_msg, sched_active_pid);
                }
                break;
                /*
            case PUBSUB_PUB_MSG:
                sprintf(pubname, "/HAW/%s/%010"PRIu32, hwaddr_str, xtimer_now_usec());
                pubsub_pub(pubname);
                ((evtimer_event_t *)&publisher)->offset = PUBSUB_PUBLISH_TIME;
                if (++publish_numbers < PUBSUB_PUBLISH_NUMBERS) {
                    evtimer_add_msg(&evtimer, &publisher, pubsub_pid);
                }
                break;
                */
            /*
            case PUBSUB_UNBLOCK_MSG:
                //gnrc_netapi_set(pubsub_netif->pid, NETOPT_L2FILTER_RM, 0, dodag.parent.face.face_addr, dodag.parent.face.face_addr_len);
                break;
            */
            case PUBSUB_TX_NAM_ACK_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                if(nce && nce->in_use) {
                    pubsub_send_nam_ack(&dodag, nce);
                }
                break;
            case PUBSUB_PUB_AUTOMATED_MSG:
                if (publish_numbers < PUBSUB_MAX_PUBLISHES) {
#ifdef NOPUBSUB
                    xtimer_remove(&pubsub_pam_timer);
                    sprintf(pubname, "/HAW/%s/%010"PRIu32, root_str, xtimer_now_usec());
                    printf("p;%d;%s;%s;%d\n", dodag.rank, pubname, parent_str, dodag.parent.alive);
                    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(pubname, CCNL_SUITE_NDNTLV, NULL, NULL);
                    ccnl_send_interest(prefix, NULL, 0, NULL);
                    ccnl_prefix_free(prefix);
#else
                    sprintf(pubname, "/HAW/%s/%010"PRIu32, hwaddr_str, xtimer_now_usec());
                    res = pubsub_pub(pubname);
#endif

                    if (res) {
                        publish_numbers++;
                    }

                    publisher_automated.msg.type = PUBSUB_PUB_AUTOMATED_MSG;
                    ((evtimer_event_t *)&(publisher_automated))->offset = PUBSUB_PUB_AUTOMATED_TIME;
                    evtimer_add_msg(&evtimer, &publisher_automated, pubsub_pid);
                }
                break;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                pkt = (gnrc_pktsnip_t *)msg.content.ptr;
                netif_snip = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_NETIF);
                if (netif_snip) {
                    netif_hdr = (gnrc_netif_hdr_t *) netif_snip->data;
                    pubsub_dispatcher(relay, &dodag, pkt->data, pkt->size,
                                      gnrc_netif_hdr_get_src_addr(netif_hdr), netif_hdr->src_l2addr_len,
                                      gnrc_netif_hdr_get_dst_addr(netif_hdr), netif_hdr->dst_l2addr_len);
                }
                gnrc_pktbuf_release(pkt);
                break;
        }
    }
}

int pubsub_show(int argc, char **argv)
{
    (void) argv;
    if (argc == 1) {
        ccnl_cs_dump(&ccnl_relay);
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

int pubsub_root(int argc, char **argv)
{
    if (argc == 2) {
        compas_dodag_init_root(&dodag, (const char *)argv[1], strlen(argv[1]));
        compas_dodag_print(&dodag);
        trickle_init(&dodag.trickle, TRICKLE_IMIN, TRICKLE_IMAX, TRICKLE_REDCONST);
        uint64_t trickle_int = trickle_next(&dodag.trickle);
        xtimer_set_msg64(&pubsub_pam_timer, trickle_int * MS_PER_SEC,
                         &pubsub_pam_msg, pubsub_pid);
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

int pubsub_publish_cmd(int argc, char **argv)
{
    if (argc == 3) {
        pubsub_pub(argv[1]);
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

int pubsub_publish_automated_cmd(int argc, char **argv)
{
    (void) argv;
    if (argc == 1) {
        if (dodag.rank != COMPAS_DODAG_ROOT_RANK) {
            publisher_automated.msg.type = PUBSUB_PUB_AUTOMATED_MSG;
            ((evtimer_event_t *)&(publisher_automated))->offset = PUBSUB_PUB_AUTOMATED_TIME;
            evtimer_add_msg(&evtimer, &publisher_automated, pubsub_pid);
        }
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "pr", "start pubsub root", pubsub_root },
    { "pp", "publish content", pubsub_publish_cmd },
    { "sc", "show content", pubsub_show },
    { "ppa", "publish content automated", pubsub_publish_automated_cmd },
    { NULL, NULL, NULL }
};

int main(void)
{
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_q, MAIN_QSZ);

    ccnl_core_init();

    ccnl_start();

    if (((pubsub_netif = gnrc_netif_iter(NULL)) == NULL) ||
        (ccnl_open_netif(pubsub_netif->pid, GNRC_NETTYPE_CCN) < 0)) {
        return -1;
    }

    uint16_t chan = 11;
    //uint8_t csma_retries = 3;
    //uint16_t tx_power = 1024;
    //netopt_enable_t preloading = NETOPT_DISABLE;
    //netopt_enable_t csma = NETOPT_DISABLE;
    //uint8_t retries = 4;
    //netopt_enable_t cca = NETOPT_DISABLE;
    gnrc_netapi_set(pubsub_netif->pid, NETOPT_CHANNEL, 0, &chan, sizeof(chan));
    //gnrc_netapi_set(pubsub_netif->pid, NETOPT_TX_POWER, 0, &tx_power, sizeof(tx_power));
    //gnrc_netapi_set(pubsub_netif->pid, NETOPT_PRELOADING, 0, &preloading, sizeof(preloading));
    //gnrc_netapi_set(pubsub_netif->pid, NETOPT_RETRANS, 0, &retries, sizeof(retries));
    //gnrc_netapi_set(pubsub_netif->pid, NETOPT_CSMA, 0, &csma, sizeof(csma));
    //gnrc_netapi_set(pubsub_netif->pid, NETOPT_CSMA_RETRIES, 0, &csma_retries, sizeof(csma_retries));
    //gnrc_netapi_set(pubsub_netif->pid, NETOPT_AUTOCCA, 0, &cca, sizeof(netopt_enable_t));

    uint16_t src_len = 8U;
    gnrc_netapi_set(pubsub_netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
#ifdef BOARD_NATIVE
    gnrc_netapi_get(pubsub_netif->pid, NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
#else
    gnrc_netapi_get(pubsub_netif->pid, NETOPT_ADDRESS_LONG, 0, hwaddr, sizeof(hwaddr));
#endif
    gnrc_netif_addr_to_str(hwaddr, sizeof(hwaddr), hwaddr_str);
    printf("d;%s\n", hwaddr_str);

    pubsub_pid = thread_create(pubsub_stack, sizeof(pubsub_stack), THREAD_PRIORITY_MAIN - 1,
                              THREAD_CREATE_STACKTEST, pubsub, &ccnl_relay,
                              "pubsub");

    if (pubsub_pid <= KERNEL_PID_UNDEF) {
        return 1;
    }

#ifndef BOARD_NATIVE
    random_init(*(uint32_t *)(hwaddr+4));
#endif

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
