/*
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ng_rpl_bloom    RPL-Bloom Extension
 * @ingroup     net_ng_rpl
 * @{
 *
 * @file
 * @brief       RPL-Bloom exntension data structs
 *
 * Header file, which defines functionalities used by RPL-Bloom.
 *
 * @author      Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#ifndef NG_RPL_BLOOM_H_
#define NG_RPL_BLOOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "net/ng_ipv6.h"
#include "net/ng_rpl/structs.h"
#include "bloom.h"

/**
 * @name ON-DODAG RPL Bloom Filter configuration
 * @{
 */
#define NG_RPL_BLOOM_ONDODAG_SIZE               (64)
#define NG_RPL_BLOOM_ONDODAG_HASHES_NUMOF       (8)
/** @} */

/**
 * @name OFF-DODAG RPL Bloom Filter configuration
 * @{
 */
#define NG_RPL_BLOOM_OFFDODAG_SIZE              (64)
#define NG_RPL_BLOOM_OFFDODAG_HASHES_NUMOF      (8)
/** @} */

/**
 * @name RPL Control Message Options
 * @{
 */
#define NG_RPL_OPT_PARENT_ANNOUNCEMENT          (11)
#define NG_RPL_OPT_NHOOD_ONDODAG_ANNOUNCEMENT   (12)
#define NG_RPL_OPT_NHOOD_OFFDODAG_ANNOUNCEMENT  (13)
/** @} */

/**
 * @name RPL Control Message Options lengths
 * @{
 */
#define NG_RPL_OPT_PARENT_ANNOUNCEMENT_LEN                  \
            (sizeof(ng_rpl_opt_parent_announcement_t) - sizeof(ng_rpl_opt_t))
#define NG_RPL_OPT_NHOOD_ONDODAG_ANNOUNCEMENT_LEN           \
            (sizeof(ng_rpl_opt_nhood_ondodag_announcement_t) - sizeof(ng_rpl_opt_t))
#define NG_RPL_OPT_NHOOD_OFFDODAG_ANNOUNCEMENT_LEN          \
            (sizeof(ng_rpl_opt_nhood_offdodag_announcement_t) - sizeof(ng_rpl_opt_t))
/** @} */

/**
 * @brief DODAG Parent Announcement
 */
typedef struct __attribute__((packed)) {
    uint8_t type;               /**< option type */
    uint8_t length;             /**< option length without the first two bytes */
    uint8_t prefix_length;      /**< number of valid leading bits */
    ng_ipv6_addr_t parent;      /**< address of the parent */
} ng_rpl_opt_parent_announcement_t;

/**
 * @brief ON-DODAG Neighborhood Announcement
 */
typedef struct __attribute__((packed)) {
    uint8_t type;                               /**< option type */
    uint8_t length;                             /**< option length without the first two bytes */
    uint8_t bloom[NG_RPL_BLOOM_ONDODAG_SIZE];   /**< neighborhood bloom filer */
} ng_rpl_opt_nhood_ondodag_announcement_t;

/**
 * @brief OFF-DODAG Neighborhood Announcement
 */
typedef struct __attribute__((packed)) {
    uint8_t type;                               /**< option type */
    uint8_t length;                             /**< option length without the first two bytes */
    uint8_t bloom[NG_RPL_BLOOM_OFFDODAG_SIZE];  /**< neighborhood bloom filer */
} ng_rpl_opt_nhood_offdodag_announcement_t;

/**
 * @brief   Add the @p src address to the neighborhood bloom filter of the @p dodag
 *          if the announced parent matches any of the configured addresses
 *
 * @param[in] dodag             Pointer to the DODAG
 * @param[in] src               IPv6 address of the sender
 * @param[in] pa                Parent Announcement
 *
 * @return true, if the announced parent address matches any of the configured addresses
 * @return false, otherwise
 */
bool ng_rpl_bloom_add_neighbor(ng_rpl_dodag_t *dodag, ng_ipv6_addr_t *src,
                                ng_rpl_opt_parent_announcement_t *pa);

/**
 * @brief   Initialize the neighborhood bloom filters of the @p dodag
 *
 * @param[in] dodag             Pointer to the DODAG
 */
bloom_t *ng_rpl_bloom_neighborhood_init(ng_rpl_dodag_t *dodag);

#ifdef __cplusplus
}
#endif

#endif /* NG_RPL_BLOOM_H_ */
/**
 * @}
 */
