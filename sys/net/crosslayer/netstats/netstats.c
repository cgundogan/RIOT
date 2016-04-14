/*
 * Copyright (C) 2016 INRIA
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 * @ingroup     net_netstats
 * @file
 * @brief       This file contains functionality to stringify netstats_module_t
 *
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 * @}
 */

#include "net/netstats.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *netstats_module_to_str(netstats_module_t module)
{
    switch (module) {
        case NETSTATS_LAYER2:
            return "Layer 2";
        case NETSTATS_IPV6:
            return "IPv6";
        case NETSTATS_ALL:
            return "all";
        default:
            return "Unknown";
    }
}

#ifdef __cplusplus
}
#endif
