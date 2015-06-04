/*
 * Copyright (C) 2013 Stephan Arndt <arndtste@zedat.fu-berlin.de>
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     ng_etx_beaconing
 * @{
 * @file
 * @brief       ETX-beaconing implementation
 *
 * Implementation for ETX-based beaconing.
 *
 * @author  Stephan Arndt <arndtste@zedat.fu-berlin.de>
 * @author  Cenk Gündoğan <cnkgndgn@gmail.com>
 * @}
 */

#include "net/ng_etx_beaconing.h"

#define ENABLE_DEBUG        (0)
#include "debug.h"

static void *_event_loop(void *args);
static void _receive(ng_pktsnip_t *pkt);
static void _send(void);
static bool _get_add_neighbor(uint8_t *l2_addr, uint8_t l2_addr_len, ng_etx_container_t **neighbor);
static ng_pktsnip_t *_build_netif_hdr(ng_pktsnip_t *payload, uint8_t *src, uint8_t src_len,
        uint8_t *dst, uint8_t dst_len);
static void _updateETX(ng_etx_container_t *neighbor);
static void _calculate_etx(ng_etx_container_t *neighbor);

static char _stack[NG_ETX_BEACONING_STACK_SIZE];
static kernel_pid_t _pid = KERNEL_PID_UNDEF;
static kernel_pid_t _if_pid = KERNEL_PID_UNDEF;
static uint8_t _my_l2_addr[NG_NETIF_HDR_L2ADDR_MAX_LEN];
static uint8_t _my_l2_addr_len;
static timex_t _beaconing_time;
static vtimer_t _beaconing_timer;

ng_etx_container_t ng_etx_neighbors[NG_ETX_BEACONING_NEIGHBORS_NUMOF];

kernel_pid_t ng_etx_beaconing_init(kernel_pid_t if_pid)
{
    _if_pid = if_pid;

    _my_l2_addr_len = ng_netapi_get(if_pid, NETCONF_OPT_ADDRESS, 0, _my_l2_addr,
            sizeof(_my_l2_addr));

    if (_pid == KERNEL_PID_UNDEF) {
        _pid = thread_create(_stack, sizeof(_stack), NG_ETX_BEACONING_PRIO,
                             CREATE_STACKTEST, _event_loop, NULL, "etx_beaconing");

        _beaconing_time = timex_set(NG_ETX_BEACONING_INTERVAL, (rand() % 1000));
        vtimer_remove(&_beaconing_timer);
        vtimer_set_msg(&_beaconing_timer, _beaconing_time, _pid, NG_ETX_BEACONING_MSG_TYPE_BEACON,
                NULL);
    }

    return _pid;
}

static void _calculate_etx(ng_etx_container_t *neighbor)
{
    neighbor->etx = 0;
    for (uint8_t i = 0; i < NG_ETX_BEACONING_WINDOW; i++) {
        neighbor->etx += neighbor->etx_window[i];
    }
    neighbor->etx /= NG_ETX_BEACONING_WINDOW;
    return;
}

static bool _get_add_neighbor(uint8_t *l2_addr, uint8_t l2_addr_len, ng_etx_container_t **neighbor)
{
    bool first = true;
    *neighbor = NULL;

    for (uint8_t i = 0; i < NG_ETX_BEACONING_NEIGHBORS_NUMOF; i++) {
        /* save position to the first unused container */
        if ((ng_etx_neighbors[i].used == false) && first) {
            DEBUG("etx: found free container\n");
            *neighbor = &ng_etx_neighbors[i];
            first = false;
            continue;
        }
        /* return false if container exists */
        else if ((ng_etx_neighbors[i].used == true) &&
                (memcmp(ng_etx_neighbors[i].l2_addr, l2_addr, l2_addr_len) == 0)) {
            DEBUG("etx: found container\n");
            *neighbor = &ng_etx_neighbors[i];
            return false;
        }
    }

    if (*neighbor != NULL) {
        DEBUG("etx: added new container\n");
        (*neighbor)->used = true;
        memcpy((*neighbor)->l2_addr, l2_addr, l2_addr_len);
        (*neighbor)->l2_addr_len = l2_addr_len;
        (*neighbor)->current_window = 0;
        (*neighbor)->recvd_in_round = false;
        for (uint8_t i = 0; i < NG_ETX_BEACONING_WINDOW; i++) {
            (*neighbor)->etx_window[i] += NG_ETX_BEACONING_PENALTY;
        }
        _calculate_etx(*neighbor);
        (*neighbor)->etx /= NG_ETX_BEACONING_WINDOW;
        return true;
    }

    /* no space left in neighbor list */
    DEBUG("etx: could not allocate a new neighbor\n");
    *neighbor = NULL;
    return false;
}

static void *_event_loop(void *args)
{
    msg_t msg, reply, msg_q[NG_ETX_BEACONING_MSG_QUEUE_SIZE];
    ng_netreg_entry_t me_reg;

    (void)args;
    int receiver_num = 0;
    ng_pktsnip_t *pkt;
    msg_init_queue(msg_q, NG_ETX_BEACONING_MSG_QUEUE_SIZE);

    me_reg.demux_ctx = NG_NETREG_DEMUX_CTX_ALL;
    me_reg.pid = thread_getpid();

    /* register interest in all l2 frames */
    ng_netreg_register(NG_NETTYPE_UNDEF, &me_reg);

    /* preinitialize ACK */
    reply.type = NG_NETAPI_MSG_TYPE_ACK;
    while (1) {
        DEBUG("etx: waiting for incoming message.\n");
        msg_receive(&msg);

        switch (msg.type) {
            case NG_ETX_BEACONING_MSG_TYPE_BEACON:
                DEBUG("etx: NG_ETX_BEACONING_MSG_TYPE_BEACON\n");
                _send();
                _beaconing_time = timex_set(NG_ETX_BEACONING_INTERVAL, (rand() % 1000));
                vtimer_set_msg(&_beaconing_timer, _beaconing_time, _pid,
                        NG_ETX_BEACONING_MSG_TYPE_BEACON, NULL);
                break;
            case NG_NETAPI_MSG_TYPE_RCV:
                DEBUG("etx: NG_NETAPI_MSG_TYPE_RCV received\n");
                pkt = (ng_pktsnip_t *) msg.content.ptr;
                _receive(pkt);
                receiver_num = ng_netreg_num(pkt->type, NG_NETTYPE_UNDEF);
                if (receiver_num == 0) {
                    ng_pktbuf_release(pkt);
                }
                else {
                    ng_pktbuf_hold(pkt, receiver_num - 1);
                }
                break;
            case NG_NETAPI_MSG_TYPE_SND:
            case NG_NETAPI_MSG_TYPE_GET:
            case NG_NETAPI_MSG_TYPE_SET:
                DEBUG("ext: reply to unsupported snd/get/set\n");
                reply.content.value = -ENOTSUP;
                msg_reply(&msg, &reply);
                break;
            default:
                break;
        }
    }

    return NULL;
}

static void _updateETX(ng_etx_container_t *neighbor)
{
    if ((neighbor->round == 0) || (neighbor->sent == 0) || (neighbor->recvd == 0)) {
        neighbor->etx_window[neighbor->current_window] = neighbor->etx + NG_ETX_BEACONING_PENALTY;
    }
    else {
        neighbor->etx_window[neighbor->current_window] =
            1.0/((neighbor->sent/(double) neighbor->round) *
                    (neighbor->recvd/(double) neighbor->round));
    }

    neighbor->current_window = (neighbor->current_window + 1) % NG_ETX_BEACONING_WINDOW;
    _calculate_etx(neighbor);

    return;
}

static void _receive(ng_pktsnip_t *pkt)
{
    uint8_t *l2_addr;
    ng_etx_container_t *neighbor = NULL;
    ng_netif_hdr_t *netif_hdr;
    ng_pktsnip_t *netif_pkt = pkt->next;

    if (netif_pkt->type != NG_NETTYPE_NETIF) {
        DEBUG("etx: not NETTYPE_NETIF - ignore frame\n");
        return;
    }

    netif_hdr = (ng_netif_hdr_t *) netif_pkt->data;
    l2_addr = ng_netif_hdr_get_src_addr(netif_hdr);

    bool new_neigh = _get_add_neighbor(l2_addr, netif_hdr->src_l2addr_len, &neighbor);

    if (neighbor == NULL) {
        DEBUG("etx: no neighbor found - ignore frame\n");
        return;
    }

    uint8_t *elem_count = (uint8_t *) (pkt->data);
    uint8_t *hwaddr_len = (elem_count + sizeof(*elem_count));
    uint8_t *hwaddr = (hwaddr_len + sizeof(*hwaddr_len));
    network_uint16_t *sent = (network_uint16_t *)(hwaddr + *hwaddr_len);
    for (uint8_t i = 0; i < *elem_count; i++) {
        if ((*hwaddr_len == _my_l2_addr_len) &&
                (memcmp(_my_l2_addr, hwaddr, _my_l2_addr_len) == 0)) {
            if (new_neigh || (byteorder_ntohs(*sent) < neighbor->sent)) {
                neighbor->sent = 0;
                neighbor->round = 0;
                neighbor->recvd = 0;
                neighbor->recvd_in_round = false;
            }
            else {
                neighbor->sent = byteorder_ntohs(*sent);
            }
            break;
        }
        hwaddr_len = (((uint8_t *) sent) + sizeof(*sent));
        hwaddr = hwaddr_len + sizeof(*hwaddr_len);
        sent = (network_uint16_t *)(hwaddr + *hwaddr_len);
    }

    if (!neighbor->recvd_in_round) {
        neighbor->recvd++;
        neighbor->recvd_in_round = true;
    }

    return;
}

static ng_pktsnip_t *_build_netif_hdr(ng_pktsnip_t *payload, uint8_t *src, uint8_t src_len,
        uint8_t *dst, uint8_t dst_len)
{
    ng_pktsnip_t *pkt = ng_pktbuf_add(payload, NULL,
            sizeof(ng_netif_hdr_t) + src_len + dst_len, NG_NETTYPE_NETIF);

    if (pkt == NULL) {
        return NULL;
    }

    ng_netif_hdr_init(pkt->data, src_len, dst_len);

    if (src != NULL && src_len > 0) {
        ng_netif_hdr_set_src_addr(pkt->data, src, src_len);
    }

    if (dst != NULL && dst_len > 0) {
        ng_netif_hdr_set_dst_addr(pkt->data, dst, dst_len);
    }

    return pkt;
}

static void _send(void)
{
    uint8_t content[NG_ETX_BEACONING_NEIGHBORS_NUMOF * NG_NETIF_HDR_L2ADDR_MAX_LEN];
    memset(content, 0, NG_ETX_BEACONING_NEIGHBORS_NUMOF * NG_NETIF_HDR_L2ADDR_MAX_LEN);
    ng_pktsnip_t *payload = ng_pktbuf_add(NULL, content,
            NG_ETX_BEACONING_NEIGHBORS_NUMOF * (NG_NETIF_HDR_L2ADDR_MAX_LEN + sizeof(uint8_t) +
                sizeof(uint16_t)),
            NG_NETTYPE_UNDEF);
    ng_pktsnip_t *pkt = _build_netif_hdr(payload, NULL, NG_NETIF_HDR_L2ADDR_MAX_LEN, NULL,
            NG_NETIF_HDR_L2ADDR_MAX_LEN);
    if (pkt == NULL) {
        DEBUG("etx: could not allocate new frame\n");
        return;
    }

    ng_netif_hdr_t *netif_hdr = (ng_netif_hdr_t *) pkt->data;

    netif_hdr->flags = NG_NETIF_HDR_FLAGS_BROADCAST;
    uint8_t *elem_count = (uint8_t *) (payload->data);
    uint8_t *hwaddr_len = (elem_count + sizeof(*elem_count));
    uint8_t *hwaddr = (hwaddr_len + sizeof(*hwaddr_len));
    network_uint16_t *recvd_val;
    for (uint8_t i = 0; i < NG_ETX_BEACONING_NEIGHBORS_NUMOF; i++) {
        if (ng_etx_neighbors[i].used) {
            *elem_count = *elem_count + 1;
            *hwaddr_len = ng_etx_neighbors[i].l2_addr_len;
            memcpy(hwaddr, ng_etx_neighbors[i].l2_addr, ng_etx_neighbors[i].l2_addr_len);
            recvd_val = (network_uint16_t *) (hwaddr + ng_etx_neighbors[i].l2_addr_len);
            *recvd_val = byteorder_htons(ng_etx_neighbors[i].recvd);
            hwaddr_len = (uint8_t *) (((uint8_t *) recvd_val) + sizeof(*recvd_val));
            hwaddr = (uint8_t *) (hwaddr_len + sizeof(*hwaddr_len));
            ng_etx_neighbors[i].round++;
            ng_etx_neighbors[i].recvd_in_round = false;
            _updateETX(&ng_etx_neighbors[i]);
        }
    }

    ng_netapi_send(_if_pid, pkt);
    return;
}
