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
#include "net/nanocoap/cache.h"

#define ENABLE_DEBUG    0
#include "debug.h"

typedef struct {
    int in_use;
    sock_udp_ep_t ep;
    uint8_t token[CONFIG_GCOAP_TOKENLEN];
#if IS_ACTIVE(MODULE_NANOCOAP_CACHE)
    uint8_t cache_key[CONFIG_NANOCOAP_CACHE_KEY_LENGTH];
#endif
} client_ep_t;

static uint8_t proxy_req_buf[CONFIG_GCOAP_PDU_BUF_SIZE];
static client_ep_t _client_eps[CONFIG_GCOAP_REQ_WAITING_MAX];

static int _request_matcher_forward_proxy(gcoap_listener_t *listener,
                                          const coap_resource_t **resource,
                                          const coap_pkt_t *pdu);
static ssize_t _forward_proxy_handler(coap_pkt_t* pdu, uint8_t *buf,
                                      size_t len, void *ctx);

const coap_resource_t forward_proxy_resources[] = {
    { "/", COAP_GET, _forward_proxy_handler, NULL },
};

gcoap_listener_t forward_proxy_listener = {
    &forward_proxy_resources[0],
    ARRAY_SIZE(forward_proxy_resources),
    NULL,
    NULL,
    _request_matcher_forward_proxy
};

void gcoap_forward_proxy_init(void)
{
    gcoap_register_listener(&forward_proxy_listener);

    memset(_client_eps, 0, sizeof(_client_eps));

    /* initialize the nanocoap cache operation, if compiled */
    if (IS_ACTIVE(MODULE_NANOCOAP_CACHE)) {
        nanocoap_cache_init();
    }
}

static int _request_aggregate(client_ep_t *cep) {
    if (IS_ACTIVE(MODULE_NANOCOAP_CACHE)) {
        client_ep_t *cepit;
        for (cepit = _client_eps;
             cepit < (_client_eps + CONFIG_GCOAP_REQ_WAITING_MAX);
             cepit++) {
            if ((!cepit->in_use) || (cepit == cep)) {
                continue;
            }

            if (memcmp(cepit->cache_key, cep->cache_key, CONFIG_NANOCOAP_CACHE_KEY_LENGTH) == 0)
            {
                /* cache keys as well as tokens are equal => ignore request */
                if (memcmp(cepit->token, cep->token, ARRAY_SIZE(cep->token)) == 0) {
                    DEBUG("gcoap_forward_proxy: request already exists, ignore!\n");
                    return 0;
                }
                /* only cache keys are equal => aggregate request */
                else {
                    DEBUG("gcoap_forward_proxy: request already exists, aggregate!\n");
                    return 1;
                }
            }
        }
    }

    return -1;
}

static int _cache_build_response(nanocoap_cache_entry_t *ce,
                                 coap_pkt_t *pdu,
                                 uint8_t *buf,
                                 size_t len)
{
    /* Use the same code from the cached content. Use other header
     * fields from the incoming request */
    gcoap_resp_init(pdu, buf, len, ce->response_pkt.hdr->code);
    /* copy all options and possible payload from the cached response
     * to the new response */
    unsigned header_len_req = coap_get_total_hdr_len(pdu);
    unsigned header_len_cached = coap_get_total_hdr_len(&ce->response_pkt);
    unsigned opt_payload_len = ce->response_len - header_len_cached;

    memcpy((buf + header_len_req),
           (ce->response_buf + header_len_cached),
           opt_payload_len);
    return header_len_req + opt_payload_len;
}

static int _cache_lookup_and_process(coap_pkt_t *pdu,
                                     uint8_t *buf,
                                     size_t len,
                                     client_ep_t *cep)
{
    (void) cep;

    uint8_t cache_key[SHA256_DIGEST_LENGTH];
    uint64_t now = xtimer_now_usec64();
    nanocoap_cache_key_generate(pdu, cache_key);
    nanocoap_cache_entry_t *ce = nanocoap_cache_key_lookup(cache_key);

    /* cache hit, methods are equal, and cache entry is not stale */
    if (ce &&
        (ce->request_method == coap_get_code(pdu)) &&
        (ce->max_age > now)) {
        /* use response from cache */
        return _cache_build_response(ce, pdu, buf, len);
    }

#if IS_ACTIVE(MODULE_NANOCOAP_CACHE)
    memcpy(cep->cache_key, cache_key, CONFIG_NANOCOAP_CACHE_KEY_LENGTH);
#endif

    return 0;
}


static client_ep_t *_allocate_client_ep(sock_udp_ep_t *ep, coap_pkt_t *pkt)
{
    client_ep_t *cep;
    for (cep = _client_eps;
         cep < (_client_eps + CONFIG_GCOAP_REQ_WAITING_MAX);
         cep++) {
        if (!cep->in_use) {
            cep->in_use = 1;
            memcpy(&cep->ep, ep, sizeof(*ep));
            memcpy(&cep->token, pkt->token, coap_get_token_len(pkt));
            return cep;
        }
    }
    return NULL;
}

static void _free_client_ep(client_ep_t *cep)
{
    memset(cep, 0, sizeof(*cep));
}

static int _request_matcher_forward_proxy(gcoap_listener_t *listener,
                                          const coap_resource_t **resource,
                                          const coap_pkt_t *pdu)
{
    (void) listener;

    char *offset;

    if (coap_get_proxy_uri(pdu, &offset) > 0) {
        *resource = &listener->resources[0];
        return GCOAP_RESOURCE_FOUND;
    }

    return GCOAP_RESOURCE_NO_PATH;
}

static ssize_t _forward_proxy_handler(coap_pkt_t *pdu, uint8_t *buf,
                                      size_t len, void *ctx)
{
    int pdu_len = 0;
    sock_udp_ep_t *remote = (sock_udp_ep_t *)ctx;

    pdu_len = gcoap_forward_proxy_request_process(pdu, remote);

    /* Out of memory, reply with 5.00 */
    if (pdu_len == -ENOMEM) {
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }
    /* Proxy-Uri malformed, reply with 4.02 */
    else if (pdu_len == -EINVAL) {
        return gcoap_response(pdu, buf, len, COAP_CODE_BAD_OPTION);
    }
    /* scheme not supported */
    else if (pdu_len == -EPERM) {
        return gcoap_response(pdu, buf, len, COAP_CODE_PROXYING_NOT_SUPPORTED);
    }

    return pdu_len;
}

static bool _parse_endpoint(sock_udp_ep_t *remote,
                            uri_parser_result_t *urip)
{
    char scratch[8];
    ipv6_addr_t addr;
    remote->family = AF_INET6;

    /* support IPv6 only for now */
    if (!urip->ipv6addr) {
        return false;
    }

    /* check for interface */
    if (urip->zoneid) {
        /* only works with integer based zoneids */

        if (urip->zoneid_len > (sizeof(scratch)/sizeof(scratch[0]) - 1)) {
            return false;
        }

        memcpy(scratch, urip->zoneid, urip->zoneid_len);

        scratch[urip->zoneid_len] = '\0';

        int pid = atoi(scratch);

        if (gnrc_netif_get_by_pid(pid) == NULL) {
            return false;
        }
        remote->netif = pid;
    }
    /* no interface present */
    else {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            remote->netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
        else {
            remote->netif = SOCK_ADDR_ANY_NETIF;
        }
    }

    /* parse destination address */
    if (ipv6_addr_from_buf(&addr, urip->ipv6addr, urip->ipv6addr_len) == NULL) {
        return false;
    }
    if ((remote->netif == SOCK_ADDR_ANY_NETIF) &&
        ipv6_addr_is_link_local(&addr)) {
        return false;
    }
    memcpy(&remote->addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));

    /* copy port string into scratch for atoi */
    memcpy(scratch, urip->port, urip->port_len);
    scratch[urip->port_len] = '\0';

    remote->port = atoi(scratch);

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
    client_ep_t *cep = (client_ep_t *)memo->context;

    pdu->token = coap_hdr_data_ptr(pdu->hdr);

    if (IS_ACTIVE(MODULE_NANOCOAP_CACHE)) {
        coap_pkt_t req;
        if (memo->send_limit == GCOAP_SEND_LIMIT_NON) {
            req.hdr = (coap_hdr_t *) &memo->msg.hdr_buf[0];
        }
        else {
            req.hdr = (coap_hdr_t *)memo->msg.data.pdu_buf;
        }

        size_t pdu_len = pdu->payload_len +
            (pdu->payload - (uint8_t *)pdu->hdr);
        nanocoap_cache_process(cep->cache_key, coap_get_code(&req), pdu, pdu_len);

        uint8_t cache_key[SHA256_DIGEST_LENGTH];
        memcpy(cache_key, cep->cache_key, CONFIG_NANOCOAP_CACHE_KEY_LENGTH);

        /* forward the response packet as-is to all matching clients */
        client_ep_t *cepit;
        for (cepit = _client_eps;
             cepit < (_client_eps + CONFIG_GCOAP_REQ_WAITING_MAX);
             cepit++) {

            if (!cepit->in_use) {
                continue;
            }

            if (memcmp(cepit->cache_key, cache_key, CONFIG_NANOCOAP_CACHE_KEY_LENGTH) == 0) {
                /* replace token, WARNING! currently, token must be
                 * of same length, otherwise we need to fiddle with
                 * the serialized packet */
                memcpy(pdu->token, cepit->token, coap_get_token_len(pdu));
                gcoap_forward_proxy_dispatch(
                    (uint8_t *)pdu->hdr,
                    (pdu->payload - (uint8_t *)pdu->hdr + pdu->payload_len),
                    &cepit->ep);
                _free_client_ep(cepit);
            }
        }
    }
    else {
        gcoap_forward_proxy_dispatch(
            (uint8_t *)pdu->hdr,
            (pdu->payload - (uint8_t *)pdu->hdr + pdu->payload_len),
            &cep->ep);
        _free_client_ep(cep);
    }
}

static int _gcoap_forward_proxy_add_uri_path(coap_pkt_t *pkt,
                                             uri_parser_result_t *urip)
{
    ssize_t res = coap_opt_add_chars(pkt, COAP_OPT_URI_PATH,
                                     urip->path, urip->path_len, '/');
    if (res < 0) {
        return -EINVAL;
    }

    if (urip->query) {
        res = coap_opt_add_chars(pkt, COAP_OPT_URI_QUERY,
                                 urip->query, urip->path_len, '&');
        if (res < 0) {
            return -EINVAL;
        }
    }

    return 0;
}

static int _gcoap_forward_proxy_copy_options(coap_pkt_t *pkt,
                                             coap_pkt_t *client_pkt,
                                             uri_parser_result_t *urip)
{
    /* copy all options from client_pkt to pkt */
    coap_optpos_t opt = {0, 0};
    uint8_t *value;
    bool uri_path_added = false;

    for (int i = 0; i < client_pkt->options_len; i++) {
        ssize_t optlen = coap_opt_get_next(client_pkt, &opt, &value, !i);
        if (optlen >= 0) {
            /* add URI-PATH before any larger opt num */
            if (!uri_path_added && (opt.opt_num > COAP_OPT_URI_PATH)) {
                if (_gcoap_forward_proxy_add_uri_path(pkt, urip) == -EINVAL) {
                    return -EINVAL;
                }
                uri_path_added = true;
            }
            /* skip PROXY-URI in new packet */
            if (opt.opt_num == COAP_OPT_PROXY_URI) {
                continue;
            }
            /* the actual copy operation */
            coap_opt_add_opaque(pkt, opt.opt_num, value, optlen);
        }
    }

    ssize_t len = coap_opt_finish(pkt,
                                  (client_pkt->payload_len ?
                                   COAP_OPT_FINISH_PAYLOAD :
                                   COAP_OPT_FINISH_NONE));

    /* copy payload from client_pkt to pkt */
    memcpy(pkt->payload, client_pkt->payload, client_pkt->payload_len);
    len += client_pkt->payload_len;

    return len;
}

extern int get_proxy_nexthop(ipv6_addr_t *dest, ipv6_addr_t *nexthop);
extern ssize_t forward_to_forwarders(coap_pkt_t *client_pkt,
                                     client_ep_t *client_ep,
                                     ipv6_addr_t *nexthop_addr,
                                     gcoap_resp_handler_t resp_handler);

static int _gcoap_forward_proxy_via_coap(coap_pkt_t *client_pkt,
                                         client_ep_t *client_ep,
                                         uri_parser_result_t *urip)
{
    coap_pkt_t pkt;
    sock_udp_ep_t origin_server_ep;

    ssize_t len;

    if (!_parse_endpoint(&origin_server_ep, urip)) {
        return -EINVAL;
    }

    ipv6_addr_t dest_addr, nexthop_addr;
    memcpy(dest_addr.u16, origin_server_ep.addr.ipv6, sizeof(origin_server_ep.addr.ipv6));
    int lastforwarder = get_proxy_nexthop(&dest_addr, &nexthop_addr);

    if (!lastforwarder) {
        return forward_to_forwarders(client_pkt, client_ep, &nexthop_addr, _forward_resp_handler);
    }

    unsigned token_len = coap_get_token_len(client_pkt);

    coap_pkt_init(&pkt, proxy_req_buf, CONFIG_GCOAP_PDU_BUF_SIZE, sizeof(coap_hdr_t) + token_len);

    pkt.hdr->ver_t_tkl = client_pkt->hdr->ver_t_tkl;
    pkt.hdr->code = client_pkt->hdr->code;
    pkt.hdr->id = client_pkt->hdr->id;

    if (token_len) {
        memcpy(pkt.token, client_pkt->token, token_len);
    }

    /* copy all options from client_pkt to pkt */
    len =_gcoap_forward_proxy_copy_options(&pkt, client_pkt, urip);

    if (len == -EINVAL) {
        return -EINVAL;
    }

    len = gcoap_req_send((uint8_t *)pkt.hdr, len,
                         &origin_server_ep,
                         _forward_resp_handler, (void *)client_ep);
    return len;
}

int gcoap_forward_proxy_request_process(coap_pkt_t *pkt,
                                        sock_udp_ep_t *client) {
    char *uri;
    uri_parser_result_t urip;
    ssize_t optlen = 0;

    client_ep_t *cep = _allocate_client_ep(client, pkt);

    if (!cep) {
        return -ENOMEM;
    }

    if (IS_ACTIVE(MODULE_NANOCOAP_CACHE)) {
        int pdu_len = _cache_lookup_and_process(pkt,
                                                (uint8_t *)pkt->hdr,
                                                CONFIG_GCOAP_PDU_BUF_SIZE,
                                                cep);
        /* if a valid cache entry was found, then pdu_len contains the
         * length of that response message */
        if (pdu_len > 0) {
            _free_client_ep(cep);
            return pdu_len;
        }
        /* if there was no cache hit, then we continue forwarding */
    }

    optlen = coap_get_proxy_uri(pkt, &uri);

    if (optlen < 0) {
        /* -ENOENT, -EINVAL */
        _free_client_ep(cep);
        return optlen;
    }

    int ures = uri_parser_process(&urip, (const char *) uri, optlen);

    /* cannot parse Proxy-URI option, or URI is relative */
    if (ures || (!uri_parser_is_absolute((const char *) uri, optlen))) {
        _free_client_ep(cep);
        return -EINVAL;
    }

    int res = _request_aggregate(cep);
    if (res >= 0) {
        if (res == 0) {
            _free_client_ep(cep);
        }
        return 0;
    }

    /* target is using CoAP */
    if (!strncmp("coap", urip.scheme, urip.scheme_len)) {
        int res = _gcoap_forward_proxy_via_coap(pkt, cep, &urip);
        if (res < 0) {
            _free_client_ep(cep);
            return -EINVAL;
        }
    }
    /* no other scheme supported for now */
    else {
        _free_client_ep(cep);
        return -EPERM;
    }

    return 0;
}

/** @} */
