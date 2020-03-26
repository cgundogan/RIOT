/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for
 * more details.
 */

/**
 * @defgroup    net_gcoap_forward_proxy    Gcoap Forward Proxy
 * @ingroup     net_gcoap
 * @brief       Forward proxy implementation for Gcoap
 *
 * @see <a href="https://tools.ietf.org/html/rfc7252#section-5.7.2">
 *          RFC 7252
 *      </a>
 *
 * @{
 *
 * @file
 * @brief       Definitions for the Gcoap forward proxy
 *
 * @author      Cenk Gündoğan <cenk.guendogan@haw-hamburg.de>
 */


#ifndef NET_GCOAP_FORWARD_PROXY_H
#define NET_GCOAP_FORWARD_PROXY_H

#include <stdbool.h>
#include <errno.h>

#include "net/nanocoap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Handles proxied requests
 *
 * @param[in]  pkt           Packet to parse
 * @param[in]  client_ep     Endpoint of the client
 *
 * @return    0              if parsing was successful
 * @return    -ENOTSUP       if the forward proxy is not compiled in
 * @return    -ENOENT        if @p pkt does not contain a Proxy-Uri option
 * @return    -EINVAL        if Proxy-Uri is malformed
 */
#if IS_USED(MODULE_GCOAP_FORWARD_PROXY)
int gcoap_forward_proxy_request_parse(coap_pkt_t *pkt,
                                      sock_udp_ep_t *client_ep);
#else
static inline int gcoap_forward_proxy_request_parse(coap_pkt_t *pkt,
                                                    sock_udp_ep_t *client_ep) {
    (void) pkt;
    (void) client_ep;
    return -ENOTSUP;
}
#endif /* IS_USED(MODULE_GCOAP_FORWARD_PROXY) */

#ifdef __cplusplus
}
#endif

#endif /* NET_GCOAP_FORWARD_PROXY_H */
/**
 * @}
 */
