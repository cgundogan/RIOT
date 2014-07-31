/**
 * tcp.h - Wraps all API types, constants and functions of the tcp implementation.
 *
 * Copyright (C) 2013  INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @defgroup tcp    TCP implementation
 * @ingroup net
 * @brief   This module implements the TCP transport layer protocol.
 *          This includes an (experimental) 6LoWPAN TCP header ompression.
 * @see     <a href="http://tools.ietf.org/html/draft-aayadi-6lowpan-tcphc-01">
 *              RFC draft-aayadi-6lowpan-tcphc-01 - TCP header compression for
 *                  6LoWPAN
 *          </a>
 * @{
 * @file
 * @brief   tcp functions
 * @author  Oliver Gesch <oliver.gesch@googlemail.com>
 * @author  Martin Lenders <mlenders@inf.fu-berlin.de>
 * @author  Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#ifndef TCP_H
#define TCP_H

#include "socket_base/in.h"
#include "socket_base/socket.h"
#include "socket_base/types.h"

/**
 * Initializes tcp.
 *
 * @return 0 on success, other else.
 */
int tcp_init_transport_layer(void);

#endif /* TCP_H */
