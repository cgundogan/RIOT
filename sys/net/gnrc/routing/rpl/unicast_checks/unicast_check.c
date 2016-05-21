/*
 * Copyright (C) 2016 Cenk Gündoğan <mail@cgundogan.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 *
 * @author  Cenk Gündoğan <mail@cgundogan.de>
 */

#include "net/ipv6.h"
#include "net/gnrc/ipv6/netif.h"
#include "net/gnrc.h"
#include "hashes.h"
#include "bloom.h"
#include "random.h"

#include "net/gnrc/rpl/unicast_checks.h"
#include "net/gnrc/rpl/structs.h"
#include "net/gnrc/rpl/dodag.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG
static char addr_str[IPV6_ADDR_MAX_STR_LEN];
#endif

void gnrc_rpl_unicast_check_trigger(gnrc_rpl_instance_t *inst, gnrc_rpl_parent_t *parent)
{
    if (parent->check_running) {
        return;
    }

    uint64_t now = xtimer_now64();

    if (((now - parent->last_checked) < (GNRC_RPL_DEFAULT_LIFETIME * GNRC_RPL_LIFETIME_UNIT - 5) * SEC_IN_USEC)
        && parent->bidirectional) {
        return;
    }

    parent->last_checked = now;
    parent->bidirectional = false;

    if (parent->unicast_checks >= 3) {
        gnrc_rpl_parent_remove(parent);
        gnrc_rpl_parent_update(&inst->dodag, NULL);
        return;
    }

    parent->check_running = true;
    xtimer_set_msg(&parent->unicast_checks_timer, random_uint32_range(1 * SEC_IN_MS, 1000 * SEC_IN_MS),
                   &parent->unicast_checks_msg, gnrc_rpl_pid);
}

/**
 * @}
 */
