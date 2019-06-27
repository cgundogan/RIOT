/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "xtimer.h"
#include "evtimer.h"
#include "evtimer_msg.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/netreg.h"

#include "ccnl-pkt-builder.h"
#include "ccn-lite-riot.h"
#include "ccnl-producer.h"
#include "ccnl-callbacks.h"

#include "compas/routing/dodag.h"
#include "compas/routing/nam.h"
#include "compas/routing/pam.h"
#include "compas/routing/sol.h"
#include "compas/trickle.h"

#include "net/hopp/hopp.h"

#define CCNL_ENC_HOPP (0x08)

char hopp_stack[HOPP_STACKSZ];
gnrc_netif_t *hopp_netif;
kernel_pid_t hopp_pid;

static unsigned char _out[CCNL_MAX_PACKET_SIZE];

static msg_t hopp_q[HOPP_QSZ];
static evtimer_msg_t evtimer;
compas_dodag_t dodag;
static evtimer_msg_event_t sol_msg_evt = { .msg.type = HOPP_SOL_MSG };
static evtimer_msg_event_t pam_msg_evt = { .msg.type = HOPP_PAM_MSG };
static evtimer_msg_event_t pto_msg_evt = { .msg.type = HOPP_PARENT_TIMEOUT_MSG };
static uint32_t nce_times[COMPAS_NAM_CACHE_LEN];
static evtimer_msg_event_t nam_msg_evts[COMPAS_NAM_CACHE_LEN];
static char hopp_prefix[COMPAS_NAME_LEN + 1];
static hopp_cb_published cb_published = NULL;

extern uint64_t the_time;

void hopp_set_cb_published(hopp_cb_published cb)
{
    cb_published = cb;
}

static bool hopp_send(gnrc_pktsnip_t *pkt, uint8_t *addr, uint8_t addr_len)
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

    if (gnrc_netapi_send(hopp_netif->pid, pkt) < 1) {
        puts("error: unable to send");
        gnrc_pktbuf_release(pkt);
        return false;
    }
    return true;
}

static void hopp_send_pam(compas_dodag_t *dodag, uint8_t *dst_addr, uint8_t dst_addr_len, bool redun)
{
    if (redun && (dodag->trickle.c >= dodag->trickle.k)) {
        return;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, compas_pam_len(dodag) + 2, GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("send_pam: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_HOPP;
    compas_pam_create(dodag, (compas_pam_t *) (((uint8_t *) pkt->data) + 2));
    hopp_send(pkt, dst_addr, dst_addr_len);
    print_send_pam();
}

static void hopp_parent_timeout(compas_dodag_t *dodag)
{
    (void) dodag;
/*
    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pto_msg_evt);
    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&sol_msg_evt);
    dodag->parent.alive = false;
    msg_t m = { .type = HOPP_SOL_MSG, .content.value = 0 };
    msg_try_send(&m, hopp_pid);
*/
}

static void hopp_send_sol(compas_dodag_t *dodag, bool force_bcast)
{
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, compas_sol_len() + 2, GNRC_NETTYPE_CCN);
    if (pkt == NULL) {
        puts("send_sol: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_HOPP;

    uint8_t *addr = NULL, flags = 0;
    size_t addr_len = 0;

    if (!force_bcast) {
        if ((dodag->rank != COMPAS_DODAG_UNDEF) && (dodag->sol_num < HOPP_PARENT_MAX_SOLS)) {
            addr = dodag->parent.face.face_addr;
            addr_len = dodag->parent.face.face_addr_len;
        }
        else if (dodag->parent.alive) {
            hopp_parent_timeout(dodag);
        }
        dodag->sol_num++;
    }

    compas_sol_create((compas_sol_t *) (((uint8_t *) pkt->data) + 2), flags);
    hopp_send(pkt, addr, addr_len);
    print_send_sol();
}

static void hopp_send_nam(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    if (dodag->rank == COMPAS_DODAG_UNDEF) {
        puts("send_nam: not part of a DODAG");
        return;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, 2 + sizeof(compas_nam_t) +
                                          nce->name.name_len + sizeof(compas_tlv_t), GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("send_nam: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_HOPP;
    compas_nam_t *nam = (compas_nam_t *)(((uint8_t *) pkt->data) + 2);
    compas_nam_create(nam);
    compas_nam_tlv_add_name(nam, &nce->name);

    hopp_send(pkt, dodag->parent.face.face_addr, dodag->parent.face.face_addr_len);
    print_send_nam(nce->name.name, nce->name.name_len);
}

static void hopp_handle_pam(struct ccnl_relay_s *relay,
                            compas_dodag_t *dodag, compas_pam_t *pam,
                            uint8_t *src_addr, uint8_t src_addr_len)
{
    print_recv_pam();
    uint16_t old_rank = dodag->rank;

    int state = compas_pam_parse(dodag, pam, src_addr, src_addr_len);

    if ((state == COMPAS_PAM_RET_CODE_CURRPARENT) ||
        (state == COMPAS_PAM_RET_CODE_NEWPARENT)  ||
        (state == COMPAS_PAM_RET_CODE_PARENT_WORSERANK)  ||
        (state == COMPAS_PAM_RET_CODE_NONFLOATINGDODAG_WORSERANK)) {

        if (old_rank != dodag->rank) {
            hopp_send_sol(dodag, true);
            hopp_send_pam(dodag, NULL, 0, false);
        }

        char dodag_prfx[COMPAS_PREFIX_LEN + 1];
        memcpy(dodag_prfx, dodag->prefix.prefix, dodag->prefix.prefix_len);
        dodag_prfx[dodag->prefix.prefix_len] = '\0';
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(dodag_prfx, CCNL_SUITE_NDNTLV, NULL);

        if (state == COMPAS_PAM_RET_CODE_NEWPARENT) {
            sockunion su;
            memset(&su, 0, sizeof(su));
            su.sa.sa_family = AF_PACKET;
            su.linklayer.sll_halen = src_addr_len;
            memcpy(su.linklayer.sll_addr, src_addr, src_addr_len);
            struct ccnl_face_s* from = ccnl_get_face_or_create(relay, 0, &(su.sa), sizeof(su.sa));

            from->flags |= CCNL_FACE_FLAGS_STATIC;
            ccnl_fib_rem_entry(relay, prefix, from);
            ccnl_fib_add_entry(relay, ccnl_prefix_dup(prefix), from);
            hopp_trickle_reset(dodag);
        }

        if (!dodag->parent.alive) {
            dodag->parent.alive = true;
            for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
                compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
                if (nce->in_use && compas_nam_cache_requested(nce->flags)) {
                    unsigned pos = nce - dodag->nam_cache;
                    nce->retries = COMPAS_NAM_CACHE_RETRIES;
                    nam_msg_evts[pos].msg.type = HOPP_NAM_MSG;
                    nam_msg_evts[pos].msg.content.ptr = nce;
                    evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[pos]);
                    ((evtimer_event_t *)&nam_msg_evts[pos])->offset = HOPP_NAM_PERIOD;
                    evtimer_add_msg(&evtimer, &nam_msg_evts[pos], hopp_pid);
                }
            }
        }

        ccnl_prefix_free(prefix);

        dodag->sol_num = 0;

        if ((state == COMPAS_PAM_RET_CODE_PARENT_WORSERANK) && dodag->parent.alive) {
            hopp_send_sol(dodag, true);
            hopp_parent_timeout(dodag);
            return;
        }

        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&sol_msg_evt);
        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pto_msg_evt);
        ((evtimer_event_t *)&pto_msg_evt)->offset = HOPP_PARENT_TIMEOUT_PERIOD;
        evtimer_add_msg(&evtimer, &pto_msg_evt, hopp_pid);

        return;
    }

    if (dodag->rank >= pam->rank) {
        trickle_increment_counter(&dodag->trickle);
    }

    if (state == COMPAS_PAM_RET_CODE_FLOATINGDODAG) {
        hopp_send_sol(dodag, true);
    }

    return;
}

static void hopp_nce_del(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[nce - dodag->nam_cache]);
    memset(nce, 0, sizeof(*nce));
}

void hopp_request(struct ccnl_relay_s *relay, compas_nam_cache_entry_t *nce)
{
    static unsigned char int_buf[HOPP_INTEREST_BUFSIZE];
    memcpy(hopp_prefix, nce->name.name, nce->name.name_len);
    hopp_prefix[nce->name.name_len] = '\0';
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(hopp_prefix, CCNL_SUITE_NDNTLV, NULL);
    sockunion su;
    memset(&su, 0, sizeof(su));
    su.sa.sa_family = AF_PACKET;
    su.linklayer.sll_halen = nce->face.face_addr_len;
    memcpy(su.linklayer.sll_addr, nce->face.face_addr, nce->face.face_addr_len);
    struct ccnl_face_s *to = ccnl_get_face_or_create(relay, 0, &(su.sa), sizeof(su.sa));
    to->flags |= CCNL_FACE_FLAGS_STATIC;
    memset(int_buf, 0, HOPP_INTEREST_BUFSIZE);

    msg_t ms = { .type = CCNL_MSG_CS_DEL, .content.ptr = prefix };
    msg_try_send(&ms, ccnl_event_loop_pid);

    if (ccnl_send_interest(prefix, int_buf, HOPP_INTEREST_BUFSIZE, NULL, to) < 0) {
        puts("hopp: failed to send Interest");
    }
    ccnl_prefix_free(prefix);
}

static compas_nam_cache_entry_t *hopp_nam_gc(compas_dodag_t *dodag, compas_name_t *cname, compas_face_t *face)
{
    compas_nam_cache_entry_t *n = NULL, *tmp = NULL;
    uint32_t now = xtimer_now_usec();
    for (compas_nam_cache_entry_t *nce = dodag->nam_cache; nce < (dodag->nam_cache + COMPAS_NAM_CACHE_LEN); nce++) {
        unsigned time = now - nce_times[nce - dodag->nam_cache];
        if (nce->in_use && (time > HOPP_NAM_STALE_TIME)) {
            if (!compas_nam_cache_requested(nce->flags)) {
                hopp_nce_del(dodag, nce);
                n = compas_nam_cache_add(dodag, cname, face);
                break;
            }
            else if (!tmp) {
                tmp = nce;
            }
        }
    }
    if (!n && tmp) {
        hopp_nce_del(dodag, tmp);
        n = compas_nam_cache_add(dodag, cname, face);
    }
    return n;
}

static void hopp_handle_nam(struct ccnl_relay_s *relay, compas_dodag_t *dodag,
                            compas_nam_t *nam, uint8_t *src_addr, uint8_t src_addr_len)
{
    uint16_t offset = 0;
    compas_tlv_t *tlv = NULL;

    compas_face_t face;
    compas_face_init(&face, src_addr, src_addr_len);

    while(compas_nam_tlv_iter(nam, &offset, &tlv)) {
        if (tlv->type == COMPAS_TLV_NAME) {
            compas_name_t cname;
            compas_name_init(&cname, (const char *) (tlv + 1), tlv->length);

            print_recv_nam(cname.name, cname.name_len);
            memcpy(hopp_prefix, cname.name, cname.name_len);
            hopp_prefix[cname.name_len] = '\0';
            compas_nam_cache_entry_t *n = NULL;
            if (NULL == (n = compas_nam_cache_find(dodag, &cname))) {
                if (NULL == (n = compas_nam_cache_add(dodag, &cname, &face))) {
                    if (NULL == (n = hopp_nam_gc(dodag, &cname, &face))) {
                        puts("NAM: NO SPACE LEFT");
                        return;
                    }
                }
            }
            if (n) {
                nce_times[n - dodag->nam_cache] = xtimer_now_usec();
                hopp_request(relay, n);
            }
        }
    }

    return;
}

static void hopp_handle_sol(compas_dodag_t *dodag, compas_sol_t *sol,
                            uint8_t *dst_addr, uint8_t dst_addr_len)
{
    print_recv_sol();
    if (dodag->rank == COMPAS_DODAG_UNDEF) {
        return;
    }
/*
    if (compas_sol_reset_trickle(sol->flags)) {
        hopp_trickle_reset(dodag);
    }
    else {
        hopp_send_pam(dodag, dst_addr, dst_addr_len, false);
    }
*/
    (void) sol;
    hopp_send_pam(dodag, dst_addr, dst_addr_len, false);
    return;
}

static void hopp_dispatcher(struct ccnl_relay_s *relay, compas_dodag_t *dodag, uint8_t *data, size_t data_len,
                            uint8_t *src_addr, uint8_t src_addr_len, uint8_t *dst_addr, uint8_t dst_addr_len)
{
    (void) dst_addr;
    (void) dst_addr_len;
    (void) data_len;
    if (!((data[0] == 0x80) && (data[1] == CCNL_ENC_HOPP))) {
        return;
    }
    switch (data[2]) {
        case COMPAS_MSG_TYPE_SOL:
            hopp_handle_sol(dodag, (compas_sol_t *) (data + 2), src_addr, src_addr_len);
            break;
        case COMPAS_MSG_TYPE_PAM:
            hopp_handle_pam(relay, dodag, (compas_pam_t *) (data + 2), src_addr, src_addr_len);
            break;
        case COMPAS_MSG_TYPE_NAM:
            hopp_handle_nam(relay, dodag, (compas_nam_t *) (data + 2), src_addr, src_addr_len);
            break;
        default:
            break;
    }
}

static bool check_nce(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    if (nce->in_use && compas_nam_cache_requested(nce->flags)) {
        if (nce->retries > 0) {
            nce->retries--;
            hopp_send_nam(dodag, nce);
            return true;
        }
        else {
            memcpy(hopp_prefix, nce->name.name, nce->name.name_len);
            hopp_prefix[nce->name.name_len] = '\0';
            struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(hopp_prefix, CCNL_SUITE_NDNTLV, NULL);
            msg_t mr, ms = { .type = CCNL_MSG_CS_LOOKUP, .content.ptr = prefix };
            msg_send_receive(&ms, &mr, ccnl_event_loop_pid);
            ccnl_prefix_free(prefix);
            if (!mr.content.value) {
                hopp_nce_del(dodag, nce);
            }
            dodag->sol_num = 0xFF;
            hopp_parent_timeout(dodag);
        }
    }

    return false;
}

static int content_send(struct ccnl_relay_s *relay, struct ccnl_face_s *face, struct ccnl_pkt_s *pkt) {
    (void) relay;
    (void) face;
    compas_name_t cname;
    char *s = ccnl_prefix_to_path(pkt->pfx);
    compas_name_init(&cname, s, strlen(s));
    ccnl_free(s);
    compas_nam_cache_entry_t *n = compas_nam_cache_find(&dodag, &cname);

    if (n) {
        msg_t msg = { .type = HOPP_NAM_DEL_MSG, .content.ptr = n };
        msg_try_send(&msg, hopp_pid);
    }
    return 0;
}

static int content_requested(struct ccnl_relay_s *relay, struct ccnl_face_s *from, struct ccnl_pkt_s *p)
{
    char *s = ccnl_prefix_to_path(p->pfx);

    compas_name_t cname;
    compas_name_init(&cname, s, strlen(s));
    compas_nam_cache_entry_t *n = compas_nam_cache_find(&dodag, &cname);

    if (n) {
        if (cb_published) {
            cb_published(relay, p, from);
        }

        msg_t msg = { .content.ptr = n };
        if (dodag.rank == COMPAS_DODAG_ROOT_RANK) {
            msg.type = HOPP_NAM_DEL_MSG;
        }
        else {
            n->flags |= COMPAS_NAM_CACHE_FLAGS_REQUESTED;
            n->retries = COMPAS_NAM_CACHE_RETRIES;
            msg.type = HOPP_NAM_MSG;
        }
        msg_try_send(&msg, hopp_pid);
    }

    ccnl_free(s);
    return 0;
}

typedef struct {
    compas_dodag_t *dodag;
    compas_name_t *name;
} hopp_dodag_name_tuple_t;

void *hopp(void *arg)
{
    struct ccnl_relay_s *relay = (struct ccnl_relay_s *) arg;

    msg_init_queue(hopp_q, HOPP_QSZ);
    evtimer_init_msg(&evtimer);

    memset(&dodag, 0, sizeof(dodag));

    ((evtimer_event_t *)&sol_msg_evt)->offset = HOPP_SOL_PERIOD;
    evtimer_add_msg(&evtimer, &sol_msg_evt, sched_active_pid);

    gnrc_netreg_entry_t _ne = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, sched_active_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_HOPP, &_ne);

    ccnl_set_cb_tx_on_data(content_send);
    ccnl_set_cb_rx_on_data(content_requested);

    while (1) {
        msg_t msg, msr;
        msg_receive(&msg);
        gnrc_pktsnip_t *pkt, *netif_snip;
        gnrc_netif_hdr_t *netif_hdr;
        compas_nam_cache_entry_t *nce;
        unsigned pos = 0;
        hopp_dodag_name_tuple_t *tuple = NULL;

        switch (msg.type) {
            case HOPP_SOL_MSG:
                if (dodag.rank != COMPAS_DODAG_ROOT_RANK) {
                    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&sol_msg_evt);
                    if (dodag.sol_num >= 3) {
                        if ((dodag.rank != COMPAS_DODAG_UNDEF) && !dodag.parent.alive) {
                            dodag.flags |= COMPAS_DODAG_FLAGS_FLOATING;
                            hopp_send_pam(&dodag, NULL, 0, false);
                            hopp_trickle_reset(&dodag);
                        }
                    }
                    hopp_send_sol(&dodag, false);
                    ((evtimer_event_t *)&sol_msg_evt)->offset = HOPP_SOL_PERIOD;
                    evtimer_add_msg(&evtimer, &sol_msg_evt, sched_active_pid);
                }
                break;
            case HOPP_PAM_MSG:
                if (dodag.rank != COMPAS_DODAG_UNDEF) {
                    hopp_send_pam(&dodag, NULL, 0, true);
                    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pam_msg_evt);
                    ((evtimer_event_t *)&pam_msg_evt)->offset = trickle_next(&dodag.trickle);
                    evtimer_add_msg(&evtimer, &pam_msg_evt, sched_active_pid);
                }
                break;
            case HOPP_NAM_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                pos = nce - dodag.nam_cache;
                evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[pos]);
                if (dodag.rank != COMPAS_DODAG_UNDEF) {
                    if ((dodag.parent.alive || dodag.rank == COMPAS_DODAG_ROOT_RANK) && check_nce(&dodag, nce)) {
                        nam_msg_evts[pos].msg.type = HOPP_NAM_MSG;
                        nam_msg_evts[pos].msg.content.ptr = nce;
                        ((evtimer_event_t *)&nam_msg_evts[pos])->offset = HOPP_NAM_PERIOD;
                        evtimer_add_msg(&evtimer, &nam_msg_evts[pos], sched_active_pid);
                    }
                }
                break;
            case HOPP_NAM_DEL_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                hopp_nce_del(&dodag, nce);
                break;
            case HOPP_PARENT_TIMEOUT_MSG:
                hopp_parent_timeout(&dodag);
                break;
            case HOPP_STOP_MSG:
                ccnl_set_cb_tx_on_data(NULL);
                ccnl_set_cb_rx_on_data(NULL);
                return NULL;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                pkt = (gnrc_pktsnip_t *) msg.content.ptr;
                if ((netif_snip = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_NETIF))) {
                    netif_hdr = (gnrc_netif_hdr_t *) netif_snip->data;
                    hopp_dispatcher(relay, &dodag, pkt->data, pkt->size,
                                    gnrc_netif_hdr_get_src_addr(netif_hdr), netif_hdr->src_l2addr_len,
                                    gnrc_netif_hdr_get_dst_addr(netif_hdr), netif_hdr->dst_l2addr_len);
                }
                gnrc_pktbuf_release(pkt);
                break;
            case HOPP_PUBLISH_MSG:
                tuple = (hopp_dodag_name_tuple_t *) msg.content.ptr;
                nce = NULL;

                if (NULL == (nce = compas_nam_cache_add(tuple->dodag, tuple->name, NULL))) {
                    if (NULL == (nce = hopp_nam_gc(tuple->dodag, tuple->name, NULL))) {
                        msr.content.value = false;
                        msg_reply(&msg, &msr);
                        break;
                    }
                }
                nce->flags |= COMPAS_NAM_CACHE_FLAGS_REQUESTED;
                msr.content.value = true;
                msg_reply(&msg, &msr);
                pos = nce - dodag.nam_cache;
                nce->retries = COMPAS_NAM_CACHE_RETRIES;
                nam_msg_evts[pos].msg.type = HOPP_NAM_MSG;
                nam_msg_evts[pos].msg.content.ptr = nce;
                evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[pos]);
                ((evtimer_event_t *)&nam_msg_evts[pos])->offset = 10;
                evtimer_add_msg(&evtimer, &nam_msg_evts[pos], hopp_pid);
                break;
            default:
                break;
        }
    }

    return NULL;
}

void hopp_root_start(const char *prefix, size_t prefix_len)
{
    compas_dodag_init_root(&dodag, prefix, prefix_len);
    compas_dodag_print(&dodag);
    hopp_trickle_reset(&dodag);
}

bool hopp_publish_content(const char *name, size_t name_len, unsigned char *content, size_t content_len)
{
    if (dodag.rank == COMPAS_DODAG_UNDEF) {
        return false;
    }

    static compas_name_t cname;
    compas_name_init(&cname, name, name_len);

    memcpy(hopp_prefix, cname.name, cname.name_len);
    hopp_prefix[cname.name_len] = '\0';
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(hopp_prefix, CCNL_SUITE_NDNTLV, NULL);
    size_t offs = CCNL_MAX_PACKET_SIZE, len;
    ccnl_ndntlv_prependContent(prefix, (uint8_t *) content, (size_t) content_len, NULL, NULL, &offs, _out, &content_len);
    ccnl_prefix_free(prefix);
    unsigned char *olddata, *data = olddata = _out + offs;
    uint64_t typ;
    if (ccnl_ndntlv_dehead(&data, &content_len, &typ, &len) || typ != NDN_TLV_Data) {
        return false;
    }
    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &content_len);
    struct ccnl_content_s *c = ccnl_content_new(&pk);

    hopp_dodag_name_tuple_t tuple = { .dodag = &dodag, .name = &cname};
    msg_t mr, ms = { .type = HOPP_PUBLISH_MSG, .content.ptr = &tuple };
    msg_send_receive(&ms, &mr, hopp_pid);
    if (!mr.content.value) {
        ccnl_content_free(c);
        return false;
    }

    ms.type = CCNL_MSG_CS_ADD;
    ms.content.ptr = c;
    msg_send(&ms, ccnl_event_loop_pid);

    return true;
}

void hopp_trickle_reset(compas_dodag_t *dodag)
{
    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pam_msg_evt);
    trickle_init(&dodag->trickle, HOPP_TRICKLE_IMIN, HOPP_TRICKLE_IMAX, HOPP_TRICKLE_REDCONST);
    ((evtimer_event_t *)&pam_msg_evt)->offset = trickle_next(&dodag->trickle);
    evtimer_add_msg(&evtimer, &pam_msg_evt, hopp_pid);
}
