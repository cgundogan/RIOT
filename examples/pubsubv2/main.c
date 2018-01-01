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

#include "compas/routing/dodag.h"
#include "compas/routing/nam.h"
#include "compas/routing/pam.h"
#include "compas/routing/sol.h"
#include "compas/trickle.h"

#include "evtimer.h"
#include "evtimer_msg.h"

#define MAIN_QSZ (8)
static msg_t _main_q[MAIN_QSZ];

#define TLSF_BUFFER     ((15 * 1024) / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

#define PUBSUB_STACKSZ (THREAD_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF)
static char pubsub_stack[PUBSUB_STACKSZ];
static kernel_pid_t pubsub_pid;
#define PUBSUB_QSZ  (8)
static msg_t _pubsub_q[PUBSUB_QSZ];
static gnrc_netif_t *pubsub_netif;
static struct ccnl_face_s *loopback_face;
#define CCNL_ENC_PUBSUB                 (0x08)
#define PUBSUB_SOL_PERIOD_BASE          (2000 * 1000)
#define PUBSUB_SOL_PERIOD_JITTER        (500)
#define PUBSUB_SOL_PERIOD               (PUBSUB_SOL_PERIOD_BASE + (rand() % (PUBSUB_SOL_PERIOD_JITTER * 1000)))
#define PUBSUB_PARENT_TIMEOUT_PERIOD    (30 * US_PER_SEC)
#define PUBSUB_SOL_MSG                  (0xBEF0)
#define PUBSUB_PAM_MSG                  (0xBEF1)
#define PUBSUB_NAM_MSG                  (0xBEF2)
#define PUBSUB_PARENT_TIMEOUT_MSG       (0xBFF3)
#define PUBSUB_NCACHE_DEL_MSG           (0xBFF4)
#define TRICKLE_IMIN                    (8)
#define TRICKLE_IMAX                    (20)
#define TRICKLE_REDCONST                (10)
static msg_t pubsub_sol_msg = { .type = PUBSUB_SOL_MSG };
static xtimer_t pubsub_sol_timer;
static msg_t pubsub_pam_msg = { .type = PUBSUB_PAM_MSG };
static xtimer_t pubsub_pam_timer;
static xtimer_t pubsub_parent_timeout_timer;
static msg_t pubsub_parent_timeout_msg = { .type = PUBSUB_PARENT_TIMEOUT_MSG };

evtimer_msg_t evtimer;

#define PUBSUB_PUBLISH_TIMEOUT          (250)
evtimer_msg_event_t publish_reqs[COMPAS_NAM_CACHE_LEN];

compas_dodag_t dodag;

void pubsub_parent_timeout(compas_dodag_t *dodag)
{
    puts("TIMEOUT");
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
        puts("error: unable to send\n");
        gnrc_pktbuf_release(pkt);
        return false;
    }
    return true;
}

void pubsub_send_sol(compas_dodag_t *dodag)
{
    puts("TX SOL");
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
        flags = COMPAS_SOL_FLAGS_TRICKLE;
        if (dodag->parent.alive) {
            pubsub_parent_timeout(dodag);
            puts("SOL: TIMEOUT");
        }
    }

    compas_sol_create((compas_sol_t *) (((uint8_t *) pkt->data) + 2), flags);
    pubsub_send(pkt, addr, addr_len);

    dodag->sol_num++;
}

void pubsub_send_nam(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    puts("TX NAM");
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

    pubsub_send(pkt, dodag->parent.face.face_addr, dodag->parent.face.face_addr_len);
}

void pubsub_send_pam(compas_dodag_t *dodag, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    puts("TX PAM");
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
    size_t pos = nce - dodag->nam_cache;
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

    if (!found) {
        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&publish_reqs[pos]);
        printf("DELETE NAM: %.*s\n", nce->name.name_len, nce->name.name);
        memset(nce, 0, sizeof(*nce));
        return;
    }

    if (dodag->parent.alive) {
        pubsub_send_nam(dodag, nce);
        publish_reqs[pos].msg.type = PUBSUB_NAM_MSG;
        publish_reqs[pos].msg.content.ptr = (void *) nce;
        ((evtimer_event_t *)&(publish_reqs[pos]))->offset = offset;
        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&publish_reqs[pos]);
        evtimer_add_msg(&evtimer, &publish_reqs[pos], pubsub_pid);
    }
}

void pubsub_handle_pam(struct ccnl_relay_s *relay, compas_dodag_t *dodag, compas_pam_t *pam,
                       uint8_t *src_addr, uint8_t src_addr_len, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    (void) dst_addr;
    (void) dst_addr_len;
    puts("RX PAM");
    int state = compas_pam_parse(dodag, pam, src_addr, src_addr_len);
    compas_dodag_print(dodag);

    if ((state == COMPAS_PAM_RET_CODE_CURRPARENT) ||
        (state == COMPAS_PAM_RET_CODE_NEWPARENT)  ||
        (state == COMPAS_PAM_RET_CODE_NONFLOATINGDODAG_WORSERANK)) {

        if ((state == COMPAS_PAM_RET_CODE_NEWPARENT) ||
            ((state == COMPAS_PAM_RET_CODE_CURRPARENT) && (dodag->sol_num > 3))) {
            trickle_init(&dodag->trickle, TRICKLE_IMIN, TRICKLE_IMAX, TRICKLE_REDCONST);
            uint64_t trickle_int = trickle_next(&dodag->trickle);
            xtimer_remove(&pubsub_pam_timer);
            xtimer_set_msg64(&pubsub_pam_timer, trickle_int * MS_PER_SEC,
                             &pubsub_pam_msg, sched_active_pid);
        }

        char dodag_prfx[COMPAS_PREFIX_LEN + 1];
        memcpy(dodag_prfx, dodag->prefix.prefix, dodag->prefix.prefix_len);
        dodag_prfx[dodag->prefix.prefix_len] = '\0';
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(dodag_prfx, CCNL_SUITE_NDNTLV, NULL, NULL);

        sockunion su;
        memset(&su, 0, sizeof(su));
        su.sa.sa_family = AF_PACKET;
        su.linklayer.sll_halen = src_addr_len;
        memcpy(su.linklayer.sll_addr, src_addr, src_addr_len);
        struct ccnl_face_s* from = ccnl_get_face_or_create(relay, 0, &(su.sa), sizeof(su.sa));

        ccnl_fib_rem_entry(relay, prefix, from);
        ccnl_fib_add_entry(relay, prefix, from);

        if (!dodag->parent.alive) {
            dodag->parent.alive = true;
            for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
                compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
                printf("----- nce->in_use: %d , requested: %d\n", nce->in_use, compas_nam_cache_requested(nce->flags));
                if (nce->in_use && compas_nam_cache_requested(nce->flags)) {
                    nce->retries = COMPAS_NAM_CACHE_RETRIES;
                    pubsub_publish(relay, dodag, nce, PUBSUB_PUBLISH_TIMEOUT + 50);
                }
            }
            xtimer_remove(&pubsub_sol_timer);
            dodag->sol_num = 0;
        }

        xtimer_remove(&pubsub_parent_timeout_timer);
        xtimer_set_msg(&pubsub_parent_timeout_timer, PUBSUB_PARENT_TIMEOUT_PERIOD,
                       &pubsub_parent_timeout_msg, sched_active_pid);
    }
    else if ((state == COMPAS_PAM_RET_CODE_PARENT_WORSERANK) && dodag->parent.alive) {
        printf("WORSE RANK PARENT\n");
        pubsub_parent_timeout(dodag);
    }

    return;
}

void pubsub_handle_nam(struct ccnl_relay_s *relay, compas_dodag_t *dodag, compas_nam_t *nam, uint8_t *src_addr, uint8_t src_addr_len, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    puts("RX NAM");
    (void) dst_addr;
    (void) dst_addr_len;

    uint16_t offset = 0;
    compas_tlv_t *tlv;

    while(compas_nam_tlv_iter(nam, &offset, &tlv)) {
        if (tlv->type == COMPAS_TLV_NAME) {
            compas_name_t cname;
            compas_name_init(&cname, (const char *) (tlv + 1), tlv->length);

            int nonce = rand(), len, typ, int_len;
            char name[COMPAS_NAME_LEN + 1];
            memcpy(name, cname.name, cname.name_len);
            name[cname.name_len] = '\0';
            compas_nam_cache_entry_t *n = compas_nam_cache_find(dodag, &cname);
            if (!n) {
                n = compas_nam_cache_add(dodag, &cname, NULL);
                if (!n) {
                    puts("NAM: NO SPACE LEFT");
                    continue;
                }
            }
            struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, NULL);
            struct ccnl_buf_s *interest = ccnl_mkSimpleInterest(prefix, &nonce);
            ccnl_prefix_free(prefix);
            if (interest) {
                unsigned char *start = interest->data;
                unsigned char *data = interest->data;
                len = interest->datalen;
                ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len);
                struct ccnl_pkt_s *pkt = ccnl_ndntlv_bytes2pkt(NDN_TLV_Interest, start, &data, &len);
                if (pkt) {
                    sockunion su;
                    memset(&su, 0, sizeof(su));
                    su.sa.sa_family = AF_PACKET;
                    su.linklayer.sll_halen = src_addr_len;
                    memcpy(su.linklayer.sll_addr, src_addr, src_addr_len);
                    struct ccnl_face_s* to = ccnl_get_face_or_create(relay, 0, &(su.sa), sizeof(su.sa));
                    struct ccnl_interest_s* i = ccnl_interest_new(relay, loopback_face, &pkt);
                    i->retries = CCNL_MAX_INTEREST_RETRANSMIT;
                    //ccnl_interest_append_pending(i, loopback_face);
                    ccnl_face_enqueue(relay, to, buf_dup(i->pkt->buf));
                    ccnl_interest_remove(relay, i);
                }
                ccnl_free(interest);
            }
        }
    }

    return;
}

void pubsub_handle_sol(compas_dodag_t *dodag, compas_sol_t *sol, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    puts("RX SOL");
    if ((dodag->rank == COMPAS_DODAG_UNDEF) || (compas_dodag_floating(dodag->flags))) {
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
        pubsub_send_pam(dodag, dst_addr, dst_addr_len);
    }

    return;
}

void pubsub_dispatcher(struct ccnl_relay_s *relay, compas_dodag_t *dodag, uint8_t *data, size_t data_len,
                       uint8_t *src_addr, uint8_t src_addr_len, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    if (!((data[0] == 0x80) && (data[1] == 0x08))) {
        int len, datalen = data_len, enc;
        unsigned int typ;
        unsigned char *start = data;
        unsigned char *dat = data;
        ccnl_switch_dehead(&dat, &datalen, &enc);
        ccnl_ndntlv_dehead(&dat, &datalen, (int*) &typ, &len);
        struct ccnl_pkt_s *p = ccnl_ndntlv_bytes2pkt(typ, start, &dat, &datalen);
        if (p) {
            p->type = typ;
            char *s;
            struct ccnl_content_s *c;
            switch (typ) {
                case NDN_TLV_Data:
                    c = ccnl_content_new(&p);
                    if (c) {
                        ccnl_content_add2cache(relay, c);
                        s = ccnl_prefix_to_path(c->pkt->pfx);
                        printf("added: %s\n", s);
                        compas_name_t cname;
                        compas_name_init(&cname, s, strlen(s));
                        ccnl_free(s);
                        compas_nam_cache_entry_t *n = compas_nam_cache_find(dodag, &cname);
                        if (n) {
                            if (dodag->rank == COMPAS_DODAG_ROOT_RANK) {
                                evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&publish_reqs[n - dodag->nam_cache]);
                                printf("ROOT: DELETE NAM: %.*s\n", n->name.name_len, n->name.name);
                                memset(n, 0, sizeof(*n));
                            }
                            else {
                                n->flags |= COMPAS_NAM_CACHE_FLAGS_REQUESTED;
                                pubsub_publish(relay, dodag, n, PUBSUB_PUBLISH_TIMEOUT);
                            }
                        }
                    }
                    else {
                        ccnl_pkt_free(p);
                    }
                    break;
                default:
                    ccnl_pkt_free(p);
                    break;
            }
        }
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

int handle_int(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
               struct ccnl_pkt_s *pkt) {
    (void) relay;
    (void) from;
    compas_name_t cname;
    char *s = ccnl_prefix_to_path(pkt->pfx);
    compas_name_init(&cname, s, strlen(s));
    ccnl_free(s);
    compas_nam_cache_entry_t *n = compas_nam_cache_find(&dodag, &cname);
    if (n) {
        msg_t m = { .type = PUBSUB_NCACHE_DEL_MSG, .content.ptr = (void *) n };
        msg_send(&m, pubsub_pid);
    }
    return 0;
}

void *pubsub(void *arg)
{
    struct ccnl_relay_s *relay = (struct ccnl_relay_s *) arg;

    msg_init_queue(_pubsub_q, PUBSUB_QSZ);
    evtimer_init_msg(&evtimer);

    memset(&dodag, 0, sizeof(dodag));
    xtimer_set_msg(&pubsub_sol_timer, PUBSUB_SOL_PERIOD,
                   &pubsub_sol_msg, sched_active_pid);

    gnrc_netreg_entry_t _ne = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, sched_active_pid);
    gnrc_netreg_entry_t _nedata = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, sched_active_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN, &_ne);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &_nedata);

    loopback_face = ccnl_get_face_or_create(&ccnl_relay, -1, NULL, 0);

    ccnl_set_local_producer(handle_int);

    while (1) {
        msg_t msg;
        msg_receive(&msg);
        gnrc_pktsnip_t *pkt, *netif_snip;
        gnrc_netif_hdr_t *netif_hdr;
        compas_nam_cache_entry_t *nce;

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
                    pubsub_send_pam(&dodag, NULL, 0);
                    uint64_t trickle_int = trickle_next(&dodag.trickle);
                    xtimer_set_msg64(&pubsub_pam_timer, trickle_int * MS_PER_SEC,
                                     &pubsub_pam_msg, sched_active_pid);
                }
                break;
            case PUBSUB_NAM_MSG:
                if ((dodag.rank != COMPAS_DODAG_UNDEF) && (dodag.parent.alive)) {
                    nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                    if (nce->retries > 0 && compas_nam_cache_requested(nce->flags)) {
                        nce->retries--;
                        pubsub_publish(relay, &dodag, nce, PUBSUB_PUBLISH_TIMEOUT);
                    }
                    else if ((nce->retries == 0) && (dodag.parent.alive)) {
                        pubsub_parent_timeout(&dodag);
                    }
                }
                break;
            case PUBSUB_PARENT_TIMEOUT_MSG:
                pubsub_parent_timeout(&dodag);
                break;
            case PUBSUB_NCACHE_DEL_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&publish_reqs[nce - dodag.nam_cache]);
                printf("DELETE NAM RECD INT: %.*s\n", nce->name.name_len, nce->name.name);
                memset(nce, 0, sizeof(*nce));
                break;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                pkt = (gnrc_pktsnip_t *)msg.content.ptr;
                netif_snip = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_NETIF);
                if (netif_snip) {
                    netif_hdr = (gnrc_netif_hdr_t *) netif_snip->data;
                    uint8_t data[128];
                    memcpy(data, pkt->data, pkt->size);
                    pubsub_dispatcher(relay, &dodag, data, pkt->size,
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
        compas_name_t name;
        compas_name_init(&name, argv[1], strlen(argv[1]));
        compas_nam_cache_entry_t *nce = compas_nam_cache_add(&dodag, &name, NULL);
        if (nce) {
            char prefix_n[COMPAS_NAME_LEN + 1];
            memcpy(prefix_n, name.name, name.name_len);
            prefix_n[name.name_len] = '\0';
            struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(prefix_n, CCNL_SUITE_NDNTLV, NULL, NULL);
            struct ccnl_content_s *c = ccnl_mkContentObject(prefix, (unsigned char *)argv[2], strlen(argv[2]));
            ccnl_prefix_free(prefix);
            ccnl_content_add2cache(&ccnl_relay, c);
            nce->flags |= COMPAS_NAM_CACHE_FLAGS_REQUESTED;
            pubsub_publish(&ccnl_relay, &dodag, nce, PUBSUB_PUBLISH_TIMEOUT);
        }
        else {
            puts("NAM CACHE: NO SPACE");
        }
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "pubsub_root", "start pubsub root", pubsub_root },
    { "pubsub_publish", "publish content", pubsub_publish_cmd },
    { "pubsub_show", "show content", pubsub_show },
    { NULL, NULL, NULL }
};

int main(void)
{
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_q, MAIN_QSZ);

    puts("Basic CCN-Lite example");

    ccnl_core_init();

    ccnl_start();

    if (((pubsub_netif = gnrc_netif_iter(NULL)) == NULL) ||
        (ccnl_open_netif(pubsub_netif->pid, GNRC_NETTYPE_CCN) < 0)) {
        puts("Error registering at network interface!");
        return -1;
    }

    pubsub_pid = thread_create(pubsub_stack, sizeof(pubsub_stack), THREAD_PRIORITY_MAIN - 1,
                              THREAD_CREATE_STACKTEST, pubsub, &ccnl_relay,
                              "pubsub");

    if (pubsub_pid <= KERNEL_PID_UNDEF) {
        puts("Creation of pubsub thread failed");
        return 1;
    }

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
