/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @author  Cenk Gündoğan <cenk.guendogan@haw-hamburg.de>
 */

#include "net/gcoap.h"
#include "net/gcoap/forward_proxy.h"
#include "uri_parser.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static uint8_t proxy_req_buf[CONFIG_GCOAP_PDU_BUF_SIZE];
static uint8_t scratch[48];

static bool _parse_endpoint(sock_udp_ep_t *remote,
                            uri_parser_result_t *urip)
{
    ipv6_addr_t addr;
    remote->family = AF_INET6;

    /* copy host to scratch for safe string operations with '\0' */
    if (urip->host_len >= sizeof(scratch)) {
        return false;
    }
    memcpy(scratch, urip->host, urip->host_len);
    scratch[urip->host_len] = '\0';

    char *addr_str = (char *) scratch;
    uint16_t addr_str_len = urip->host_len;

    /* support IPv6 only for now */
    if (addr_str[0] != '[') {
        return false;
    }

    /* check for interface */
    char *iface_str = strchr(addr_str, '%');
    if (iface_str) {
        /* do not count '%' and ']' */
        unsigned iface_len = addr_str_len - (iface_str - addr_str) - 2;

        /* also do not count '%' */
        addr_str_len -= iface_len + 1;

        /* skip '%' */
        iface_str++;
        iface_str[iface_len] = '\0';

        int pid = atoi(iface_str);
        if (gnrc_netif_get_by_pid(pid) == NULL) {
            return false;
        }
        remote->netif = pid;
    }
    /* no interface present in host string */
    else {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            remote->netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
        else {
            remote->netif = SOCK_ADDR_ANY_NETIF;
        }
    }

    /* skip '[' and reduce length by 2 for '[' and ']' */
    addr_str++;
    addr_str_len -= 2;

    /* replace ']' with '\0' for safe string operations */
    addr_str[addr_str_len] = '\0';

    /* parse destination address */
    if (ipv6_addr_from_str(&addr, addr_str) == NULL) {
        return false;
    }
    if ((remote->netif == SOCK_ADDR_ANY_NETIF) && ipv6_addr_is_link_local(&addr)) {
        return false;
    }
    memcpy(&remote->addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));

    /* copy port string into scratch for atoi */
    memcpy(scratch, urip->port, urip->port_len);
    scratch[urip->port_len] = '\0';

    remote->port = atoi((char *) scratch);

    if (remote->port == 0) {
        return false;
    }

    return true;
}

static void _forward_resp_handler(const gcoap_request_memo_t *memo,
                                  coap_pkt_t* pdu,
                                  const sock_udp_ep_t *remote)
{
    (void) remote; /* this is the origin server */

    /* forward the response packet as-is to the client */
    gcoap_dispatch((uint8_t *)pdu->hdr,
                   (pdu->payload - (uint8_t *)pdu->hdr + pdu->payload_len),
                   (sock_udp_ep_t *)&memo->client_ep);
}

static int _gcoap_forward_proxy_via_coap(coap_pkt_t *client_pkt,
                                         sock_udp_ep_t *client_ep,
                                         uri_parser_result_t *urip)
{
    coap_pkt_t pkt;
    sock_udp_ep_t origin_server_ep;

    gcoap_request_memo_t *memo = NULL;

    if (!_parse_endpoint(&origin_server_ep, urip)) {
        return -EINVAL;
    }

    /* do not forward requests if they already exist, e.g., due to CON
       and retransmissions. In the future, the proxy should set an
       empty ACK message to stop the retransmissions of a client */
    gcoap_find_req_memo(&memo, client_pkt, &origin_server_ep);
    if (memo) {
        DEBUG("gcoap_forward_proxy: request already exists, ignore!\n");
        return 0;
    }

    unsigned token_len = coap_get_token_len(client_pkt);

    coap_pkt_init(&pkt, proxy_req_buf,
                  (CONFIG_GCOAP_PDU_BUF_SIZE - CONFIG_GCOAP_REQ_OPTIONS_BUF),
                  sizeof(coap_hdr_t) + token_len);

    pkt.hdr->ver_t_tkl = client_pkt->hdr->ver_t_tkl;
    pkt.hdr->code = client_pkt->hdr->code;
    pkt.hdr->id = client_pkt->hdr->id;

    if (token_len) {
        memcpy(pkt.token, client_pkt->token, token_len);
    }

    ssize_t res = coap_opt_add_chars(&pkt, COAP_OPT_URI_PATH,
                                     urip->path, urip->path_len, '/');
    if (res < 0) {
        return -EINVAL;
    }

    if (urip->query) {
        res = coap_opt_add_chars(&pkt, COAP_OPT_URI_PATH,
                                 urip->query, urip->path_len, '&');
        if (res < 0) {
            return -EINVAL;
        }
    }

    /* copy all options from client_pkt to pkt */
    coap_optpos_t opt = {0, 0};
    uint8_t *value;
    for (int i = 0; i < client_pkt->options_len; i++) {
        ssize_t optlen = coap_opt_get_next(client_pkt, &opt, &value, !i);
        if (optlen >= 0) {
            if (opt.opt_num == COAP_OPT_PROXY_URI) {
                continue;
            }
            coap_opt_add_opaque(&pkt, opt.opt_num, value, optlen);
        }
    }

    ssize_t len = coap_opt_finish(&pkt,
                                  (client_pkt->payload_len ?
                                   COAP_OPT_FINISH_PAYLOAD :
                                   COAP_OPT_FINISH_NONE));

    /* copy payload from client_pkt to pkt */
    memcpy(pkt.payload, client_pkt->payload, client_pkt->payload_len);
    len += client_pkt->payload_len;

    len = gcoap_req_send_report((uint8_t *)pkt.hdr, len,
                                &origin_server_ep, &memo,
                                _forward_resp_handler, NULL);
    memcpy(&memo->client_ep, client_ep, sizeof(*client_ep));
    return 0;
}

int gcoap_forward_proxy_request_parse(coap_pkt_t *pkt, sock_udp_ep_t *client_ep) {
    char *uri;
    uri_parser_result_t urip;

    ssize_t optlen = 0;

    optlen = coap_get_proxy_uri(pkt, &uri);

    if (optlen < 0) {
        /* -ENOENT, -EINVAL */
        return optlen;
    }

    int ures = uri_parser_process(&urip, (const char *) uri, optlen);

    /* cannot parse Proxy-URI option, or URI is relative */
    if (ures || (!uri_parser_is_absolute((const char *) uri, optlen))) {
        return -EINVAL;
    }

    /* target is using CoAP */
    if (!strncmp("coap", urip.scheme, urip.scheme_len)) {
        int res = _gcoap_forward_proxy_via_coap(pkt, client_ep, &urip);
        if (res < 0) {
            return -EINVAL;
        }
    }
    /* no other scheme supported for now */
    else {
        return -EPERM;
    }

    return 0;
}

/** @} */
