/**
 * Copyright (C) 2013, 2014  INRIA.
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @author      Eric Engel <eric.engel@fu-berlin.de>
 * @author      Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#include <stdbool.h>
#include "net/af.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/ipv6/netif.h"
#include "net/gnrc/rpl/dodag.h"
#include "net/gnrc/rpl/structs.h"
#include "utlist.h"

#include "net/gnrc/rpl.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG
static char addr_str[IPV6_ADDR_MAX_STR_LEN];
#endif

static gnrc_rpl_parent_t *_gnrc_rpl_find_preferred_parent(gnrc_rpl_instance_t *instance);
static void _rpl_trickle_send_dio(void *args);

static void _rpl_trickle_send_dio(void *args)
{
    gnrc_rpl_instance_t *inst = (gnrc_rpl_instance_t *) args;
    ipv6_addr_t all_RPL_nodes = GNRC_RPL_ALL_NODES_ADDR;
    gnrc_rpl_send_DIO(inst, &all_RPL_nodes);
    DEBUG("trickle callback: Instance (%d) | DODAG: (%s)\n", inst->id,
            ipv6_addr_to_str(addr_str,&(inst->dodag.dodag_id), sizeof(addr_str)));
}

bool gnrc_rpl_instance_add(uint8_t instance_id, gnrc_rpl_instance_t **inst)
{
    *inst = NULL;
    bool first = true;
    for (uint8_t i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
        /* save position to the first unused instance */
        if ((gnrc_rpl_instances[i].state == 0) && first) {
            *inst = &gnrc_rpl_instances[i];
            first = false;
            continue;
        }
        else if ((gnrc_rpl_instances[i].state != 0) && (gnrc_rpl_instances[i].id == instance_id)) {
            DEBUG("Instance with id %d exists\n", instance_id);
            *inst = &gnrc_rpl_instances[i];
            return false;
        }
    }

    if (*inst != NULL) {
        (*inst)->id = instance_id;
        (*inst)->state = 1;
        (*inst)->max_rank_inc = GNRC_RPL_DEFAULT_MAX_RANK_INCREASE;
        (*inst)->min_hop_rank_inc = GNRC_RPL_DEFAULT_MIN_HOP_RANK_INCREASE;
        (*inst)->parents = NULL;
        return true;
    }

    /* no space available to allocate a new instance */
    DEBUG("Could not allocate a new RPL instance\n");
    *inst = NULL;
    return false;
}

bool gnrc_rpl_instance_remove_by_id(uint8_t instance_id)
{
    for(uint8_t i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
        if (gnrc_rpl_instances[i].id == instance_id) {
            return gnrc_rpl_instance_remove(&gnrc_rpl_instances[i]);
        }
    }
    return false;
}

bool gnrc_rpl_instance_remove(gnrc_rpl_instance_t *inst)
{
    gnrc_rpl_instance_remove_all_parents(inst);
    trickle_stop(&(inst->dodag.trickle));
    vtimer_remove(&(inst->dodag.dao_timer));
    vtimer_remove(&(inst->dodag.cleanup_timer));
    memset(inst, 0, sizeof(gnrc_rpl_instance_t));
    return true;
}

gnrc_rpl_instance_t *gnrc_rpl_instance_get(uint8_t instance_id)
{
    for (uint8_t i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
        if (gnrc_rpl_instances[i].id == instance_id) {
            return &gnrc_rpl_instances[i];
        }
    }
    return NULL;
}

bool gnrc_rpl_dodag_init(gnrc_rpl_instance_t *instance, ipv6_addr_t *dodag_id)
{
    if ((instance == NULL) || instance->state == 0) {
        DEBUG("Instance is NULL or unused\n");
        return false;
    }

    instance->dodag.dodag_id = *dodag_id;
    instance->dodag.prefix_len = GNRC_RPL_DEFAULT_PREFIX_LEN;
    instance->dodag.addr_preferred = GNRC_RPL_DEFAULT_PREFIX_LIFETIME;
    instance->dodag.addr_valid = GNRC_RPL_DEFAULT_PREFIX_LIFETIME;
    instance->dodag.my_rank = GNRC_RPL_INFINITE_RANK;
    instance->dodag.trickle.callback.func = &_rpl_trickle_send_dio;
    instance->dodag.trickle.callback.args = instance;
    instance->dodag.dio_interval_doubl = GNRC_RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS;
    instance->dodag.dio_min = GNRC_RPL_DEFAULT_DIO_INTERVAL_MIN;
    instance->dodag.dio_redun = GNRC_RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT;
    instance->dodag.default_lifetime = GNRC_RPL_DEFAULT_LIFETIME;
    instance->dodag.lifetime_unit = GNRC_RPL_LIFETIME_UNIT;
    instance->dodag.node_status = GNRC_RPL_NORMAL_NODE;
    instance->dodag.dao_seq = GNRC_RPL_COUNTER_INIT;
    instance->dodag.dtsn = 0;
    instance->dodag.dao_ack_received = false;
    instance->dodag.dao_counter = 0;
    instance->dodag.cleanup_time = timex_set(GNRC_RPL_CLEANUP_TIME, 0);
#ifdef MODULE_GNRC_RPL_BLOOM
    instance->bloom_ext.instance = instance;
    gnrc_rpl_bloom_instance_nhood_init(&instance->bloom_ext);
#endif

    return true;
}

void gnrc_rpl_instance_remove_all_parents(gnrc_rpl_instance_t *inst)
{
    gnrc_rpl_parent_t *elt, *tmp;
    LL_FOREACH_SAFE(inst->parents, elt, tmp) {
        gnrc_rpl_parent_remove(elt);
    }
    vtimer_remove(&(inst->dodag.cleanup_timer));
    vtimer_set_msg(&(inst->dodag.cleanup_timer), inst->dodag.cleanup_time, gnrc_rpl_pid,
            GNRC_RPL_MSG_TYPE_CLEANUP_HANDLE, inst);
}

bool gnrc_rpl_parent_add_by_addr(gnrc_rpl_instance_t *inst, ipv6_addr_t *addr,
                                 gnrc_rpl_parent_t **parent)
{
    if ((inst == NULL) || (inst->state == 0)) {
        DEBUG("Instance is NULL or unused\n");
        return false;
    }

    *parent = NULL;
    bool first = true;
    for (uint8_t i = 0; i < GNRC_RPL_PARENTS_NUMOF; ++i) {
        /* save position to the first unused instance */
        if ((gnrc_rpl_parents[i].state == 0) && first) {
            *parent = &gnrc_rpl_parents[i];
            first = false;
            continue;
        }
        /* return false if parent exists */
        else if ((gnrc_rpl_parents[i].state != 0) &&
                (gnrc_rpl_parents[i].instance->id == inst->id) &&
                ipv6_addr_equal(&(gnrc_rpl_parents[i].instance->dodag.dodag_id),
                                &(inst->dodag.dodag_id))
                && ipv6_addr_equal(&gnrc_rpl_parents[i].addr, addr)) {
            DEBUG("parent with addr: %s does exist\n", ipv6_addr_to_str(addr_str, addr,
                        sizeof(addr_str)));
            *parent = &gnrc_rpl_parents[i];
            return false;
        }
    }

    if (*parent != NULL) {
        (*parent)->instance = inst;
        LL_APPEND(inst->parents, *parent);
        (*parent)->state = 1;
        (*parent)->addr = *addr;
        if ((*parent) == (*parent)->instance->parents) {
            ipv6_addr_t all_RPL_nodes = GNRC_RPL_ALL_NODES_ADDR;
            ipv6_addr_t def = IPV6_ADDR_UNSPECIFIED;
            kernel_pid_t if_id = gnrc_ipv6_netif_find_by_addr(NULL, &all_RPL_nodes);
            if (if_id == KERNEL_PID_UNDEF) {
                DEBUG("RPL: no interface found for the parent addres\n");
                return false;
            }
            if (fib_add_entry(&gnrc_ipv6_fib_table, if_id, def.u8,
                              sizeof(ipv6_addr_t), AF_INET6,
                              inst->parents->addr.u8, sizeof(ipv6_addr_t),
                              AF_INET6, (inst->dodag.default_lifetime *
                                         inst->dodag.lifetime_unit) * SEC_IN_MS) != 0) {
                DEBUG("RPL: error adding parent to FIB\n");
                gnrc_rpl_parent_remove(*parent);
                return false;
            }
        }
#ifdef MODULE_GNRC_RPL_BLOOM
        (*parent)->bloom_ext.parent = *parent;
        gnrc_rpl_bloom_parent_nhood_init(&((*parent)->bloom_ext));
#endif
        return true;
    }

    /* no space available to allocate a new parent */
    DEBUG("Could not allocate a new parent\n");
    *parent = NULL;
    return false;
}

gnrc_rpl_parent_t *gnrc_rpl_parent_get(gnrc_rpl_instance_t *inst, ipv6_addr_t *addr)
{
    if ((inst== NULL) || (inst->state == 0)) {
        DEBUG("Instance is NULL or unused\n");
        return NULL;
    }

    gnrc_rpl_parent_t *parent = NULL;
    LL_FOREACH(inst->parents, parent) {
        if (ipv6_addr_equal(&parent->addr, addr)) {
            return parent;
        }
    }
    return NULL;
}

bool gnrc_rpl_parent_remove(gnrc_rpl_parent_t *parent)
{
    if (parent == parent->instance->parents) {
        ipv6_addr_t def = IPV6_ADDR_UNSPECIFIED;
        fib_remove_entry(&gnrc_ipv6_fib_table, def.u8, sizeof(ipv6_addr_t));
    }
    LL_DELETE(parent->instance->parents, parent);
    memset(parent, 0, sizeof(gnrc_rpl_parent_t));
    return true;
}

void gnrc_rpl_local_repair(gnrc_rpl_instance_t *inst)
{
    DEBUG("RPL: [INFO] Local Repair started\n");

    inst->dodag.dtsn++;

    if (inst->parents) {
        gnrc_rpl_instance_remove_all_parents(inst);
        ipv6_addr_t def = IPV6_ADDR_UNSPECIFIED;
        fib_remove_entry(&gnrc_ipv6_fib_table, def.u8, sizeof(ipv6_addr_t));
    }

    if (inst->dodag.my_rank != GNRC_RPL_INFINITE_RANK) {
        trickle_reset_timer(&(inst->dodag.trickle));
        vtimer_remove(&(inst->dodag.cleanup_timer));
        vtimer_set_msg(&(inst->dodag.cleanup_timer), inst->dodag.cleanup_time, gnrc_rpl_pid,
            GNRC_RPL_MSG_TYPE_CLEANUP_HANDLE, inst);
    }

    inst->dodag.my_rank = GNRC_RPL_INFINITE_RANK;
}

void gnrc_rpl_parent_update(gnrc_rpl_instance_t *instance, gnrc_rpl_parent_t *parent)
{
    uint16_t old_rank = instance->dodag.my_rank;
    timex_t now;
    vtimer_now(&now);
    ipv6_addr_t def = IPV6_ADDR_UNSPECIFIED;

    /* update Parent lifetime */
    if (parent != NULL) {
        parent->lifetime.seconds = now.seconds +
                (instance->dodag.default_lifetime * instance->dodag.lifetime_unit);
        parent->lifetime.microseconds = 0;
        if (parent == instance->parents) {
            ipv6_addr_t all_RPL_nodes = GNRC_RPL_ALL_NODES_ADDR;
            kernel_pid_t if_id;
            if ((if_id = gnrc_ipv6_netif_find_by_addr(NULL, &all_RPL_nodes)) != KERNEL_PID_UNDEF) {
                fib_add_entry(&gnrc_ipv6_fib_table, if_id, def.u8,
                              sizeof(ipv6_addr_t), AF_INET6,
                              instance->parents->addr.u8, sizeof(ipv6_addr_t),
                              AF_INET6, (instance->dodag.default_lifetime *
                                         instance->dodag.lifetime_unit) * SEC_IN_MS);
            }
        }
    }

    if (_gnrc_rpl_find_preferred_parent(instance) == NULL) {
        gnrc_rpl_local_repair(instance);
    }

    if (instance->parents && (old_rank != instance->dodag.my_rank)) {
        trickle_reset_timer((&instance->dodag.trickle));
    }
}

/**
 * @brief   Find the parent with the lowest rank and update the instance's preferred parent
 *
 * @param[in] instance  Pointer to the RPL instance
 *
 * @return  Pointer to the preferred parent, on success.
 * @return  NULL, otherwise.
 */
static gnrc_rpl_parent_t *_gnrc_rpl_find_preferred_parent(gnrc_rpl_instance_t *inst)
{
    ipv6_addr_t def = IPV6_ADDR_UNSPECIFIED;
    gnrc_rpl_parent_t *old_best = inst->parents;
    gnrc_rpl_parent_t *new_best = old_best;
    uint16_t old_rank = inst->dodag.my_rank;
    gnrc_rpl_parent_t *elt = NULL, *tmp = NULL;

    if (inst->parents == NULL) {
        return NULL;
    }

    LL_FOREACH_SAFE(inst->parents, elt, tmp) {
        new_best = new_best->instance->of->which_parent(new_best, elt);
    }

    if (new_best != old_best) {
        LL_DELETE(inst->parents, new_best);
        LL_PREPEND(inst->parents, new_best);
        if (inst->mop != GNRC_RPL_MOP_NO_DOWNWARD_ROUTES) {
            gnrc_rpl_send_DAO(inst, &old_best->addr, 0);
            gnrc_rpl_delay_dao(inst);
        }
        fib_remove_entry(&gnrc_ipv6_fib_table, def.u8, sizeof(ipv6_addr_t));
        ipv6_addr_t all_RPL_nodes = GNRC_RPL_ALL_NODES_ADDR;

        kernel_pid_t if_id = gnrc_ipv6_netif_find_by_addr(NULL, &all_RPL_nodes);

        if (if_id == KERNEL_PID_UNDEF) {
            DEBUG("RPL: no interface found for the parent address\n");
            return NULL;
        }

        fib_add_entry(&gnrc_ipv6_fib_table, if_id, def.u8, sizeof(ipv6_addr_t),
                      AF_INET6, inst->parents->addr.u8, sizeof(ipv6_addr_t),
                      AF_INET6, (inst->dodag.default_lifetime *
                                 inst->dodag.lifetime_unit) * SEC_IN_MS);
    }

    inst->dodag.my_rank = inst->of->calc_rank(inst->parents, 0);
    if (inst->dodag.my_rank != old_rank) {
        trickle_reset_timer(&(inst->dodag.trickle));
    }

    elt = NULL; tmp = NULL;
    LL_FOREACH_SAFE(inst->parents, elt, tmp) {
        if (DAGRANK(inst->dodag.my_rank, inst->min_hop_rank_inc)
            <= DAGRANK(elt->rank, inst->min_hop_rank_inc)) {
            gnrc_rpl_parent_remove(elt);
        }
    }

    return inst->parents;
}

gnrc_rpl_instance_t *gnrc_rpl_root_dodag_init(uint8_t instance_id, ipv6_addr_t *dodag_id,
                                              uint8_t mop)
{
    if (gnrc_rpl_pid == KERNEL_PID_UNDEF) {
        DEBUG("RPL: RPL thread not started\n");
        return NULL;
    }

    ipv6_addr_t *configured_addr;
    gnrc_ipv6_netif_addr_t *netif_addr = NULL;
    gnrc_rpl_instance_t *inst = NULL;

    if (gnrc_ipv6_netif_find_by_addr(&configured_addr, dodag_id) == KERNEL_PID_UNDEF) {
        DEBUG("RPL: no IPv6 address configured to match the given dodag id: %s\n",
              ipv6_addr_to_str(addr_str, dodag_id, sizeof(addr_str)));
        return NULL;
    }

    if ((netif_addr = gnrc_ipv6_netif_addr_get(configured_addr)) == NULL) {
        DEBUG("RPL: no netif address found for %s\n", ipv6_addr_to_str(addr_str, configured_addr,
                sizeof(addr_str)));
        return NULL;
    }

    if (gnrc_rpl_instance_add(instance_id, &inst)) {
        inst->of = (gnrc_rpl_of_t *) gnrc_rpl_get_of_for_ocp(GNRC_RPL_DEFAULT_OCP);
        inst->mop = mop;
        inst->min_hop_rank_inc = GNRC_RPL_DEFAULT_MIN_HOP_RANK_INCREASE;
        inst->max_rank_inc = GNRC_RPL_DEFAULT_MAX_RANK_INCREASE;
    }
    else if (inst == NULL) {
        DEBUG("RPL: could not allocate memory for a new instance with id %d", instance_id);
        return NULL;
    }
    else {
        DEBUG("RPL: instance (%d) exists", instance_id);
        return NULL;
    }

    if (!gnrc_rpl_dodag_init(inst, dodag_id)) {
        DEBUG("RPL: could not initialize DODAG");
        return NULL;
    }

    inst->dodag.prefix_len = netif_addr->prefix_len;
    inst->dodag.addr_preferred = netif_addr->preferred;
    inst->dodag.addr_valid = netif_addr->valid;

    return inst;
}

/**
 * @}
 */
