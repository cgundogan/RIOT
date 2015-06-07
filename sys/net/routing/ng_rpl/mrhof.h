/*
 * Copyright (C) 2014 Oliver Hahm <oliver.hahm@inria.fr>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_ng_rpl
 * @{
 * @file
 * @brief       Minimum Rank with Hysteresis Objective Function.
 *
 * @author      Eric Engel <eric.engel@fu-berlin.de>
 * @author      Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#ifndef OF0_H
#define OF0_H

#include "net/ng_rpl/structs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Maximum allowed value for the path metric of a selected path.
 * @see <a href="https://tools.ietf.org/html/rfc6719#section-5">
 *          MRHOF Variables and Parameters
 *      </a>
 */
#ifndef NG_RPL_MAX_PATH_COST
#define NG_RPL_MAX_PATH_COST (0x8000)
#endif

/**
 * @brief   Maximum allowed value for the selected link metric for each link on the path.
 * @see <a href="https://tools.ietf.org/html/rfc6719#section-5">
 *          MRHOF Variables and Parameters
 *      </a>
 */
#ifndef NG_RPL_MAX_LINK_METRIC
#define NG_RPL_MAX_LINK_METRIC (512)
#endif

/**
 * @brief   ETX rank multiplier
 * @see <a href="https://tools.ietf.org/html/rfc6551#section-4.3.2">
 *          The ETX Reliability Object
 *      </a>
 */
#ifndef NG_RPL_ETX_RANK_MULTIPLIER
#define NG_RPL_ETX_RANK_MULTIPLIER (0x80)
#endif

/**
 * @brief   The difference between the cost of the path through the preferred parent and the
 *          minimum cost path in order to trigger the selection of a new preferred parent.
 * @see <a href="https://tools.ietf.org/html/rfc6719#section-5">
 *          MRHOF Variables and Parameters
 *      </a>
 */
#ifndef NG_RPL_PARENT_SWITCH_THRESHOLD
#define NG_RPL_PARENT_SWITCH_THRESHOLD (192)
#endif

/**
 * @brief   Return the address to the mrhof objective function
 *
 * @return  Address of the mrhof objective function
 */
ng_rpl_of_t *ng_rpl_get_mrhof(void);

#ifdef __cplusplus
}
#endif

#endif /* OF0_H */
/**
 * @}
 */
