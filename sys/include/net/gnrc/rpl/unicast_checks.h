/*
 * Copyright (C) 2016 Cenk Gündoğan <mail@cgundogan.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup net_gnrc_rpl
 * @{
 *
 * @file
 * @brief       Unicast Checks related functions for RPL
 *
 * Header file, which defines all public known unicast checks related functions for RPL.
 *
 * @author      Cenk Gündoğan <mail@cgundogan.de>
 */

#ifndef GNRC_RPL_UNICAST_CHECKS_H_
#define GNRC_RPL_UNICAST_CHECKS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "net/gnrc/rpl/structs.h"

#define GNRC_RPL_UNICAST_CHECKS_DIS_MSG_TYPE (0x9189)

/**
 * @brief   Trigger link check for @p parent of @p inst.
 *
 * @param[in] inst      Pointer to the Instance
 * @param[in] parent    Pointer to the parent
 */
void gnrc_rpl_unicast_check_trigger(gnrc_rpl_instance_t *inst, gnrc_rpl_parent_t *parent);
#ifdef __cplusplus
}
#endif

#endif /* GNRC_RPL_UNICAST_CHECKS_H_ */
/**
 * @}
 */
