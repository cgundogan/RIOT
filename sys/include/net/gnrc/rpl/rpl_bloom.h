/*
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_gnrc_rpl_bloom  RPL-Bloom
 * @ingroup     net_gnrc_rpl
 * @{
 *
 * @file
 * @brief       RPL-Bloom data structs
 *
 * Header file, which defines functionalities used by RPL-Bloom.
 *
 * @author      Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#ifndef GNRC_RPL_BlOOM_H_
#define GNRC_RPL_BlOOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "net/ipv6/addr.h"
#include "net/gnrc/rpl/structs.h"
#include "bloom.h"

/**
 * @name RPL-Bloom configuration
 * @{
 */
/**
 * @brief Size of the Bloom Filter in Bits
 */
#define GNRC_RPL_BLOOM_SIZE                 (64)

/**
 * @brief Number of hashes for the Bloom Filter
 */
#define GNRC_RPL_BLOOM_HASHES_NUMOF         (8)
/** @} */

/**
 * @name RPL-Bloom Control Message Options
 * @{
*/
#define GNRC_RPL_OPT_PARENT_ANNOUNCEMENT    (11)
#define GNRC_RPL_OPT_NHOOD_ANNOUNCEMENT     (12)
/** @} */

/**
 * @name RPL-Bloom Control Message Options lengths
 * @{
 */
/**
 * @brief Length for the Parent Announcement RPL-Bloom DIO control message option
 */
#define GNRC_RPL_OPT_PA_LEN                 (sizeof(gnrc_rpl_opt_pa_t) - sizeof(gnrc_rpl_opt_t))

/**
 * @brief Length for the Neighborhood Announcement RPL-Bloom DIO control message option
 */
#define GNRC_RPL_OPT_NA_LEN                 (sizeof(gnrc_rpl_opt_na_t) - sizeof(gnrc_rpl_opt_t))
/** @} */

/**
 * @brief Most significant bit of the rank
 */
#define GNRC_RPL_BLOOM_MSB                  (1U << 15)

/**
 * @brief Check interval in micro seconds
 */
#define GNRC_RPL_BLOOM_INTERVAL             (120 * SEC_IN_USEC)

extern uint32_t gnrc_rpl_bloom_checked_at;

/**
 * @brief RPL-Bloom Parent Announcement
 */
typedef struct __attribute__((packed)) {
    uint8_t type;                           /**< option type */
    uint8_t length;                         /**< option length without the first two bytes */
    uint8_t prefix_len;                     /**< prefix length of the preferred parent */
} gnrc_rpl_opt_pa_t;

/**
 * @brief RPL-Bloom Neighborhood Announcement
 */
typedef struct __attribute__((packed)) {
    uint8_t type;                           /**< option type */
    uint8_t length;                         /**< option length without the first two bytes */
    uint8_t bloom[GNRC_RPL_BLOOM_SIZE/8];   /**< neighborhood bloom filer */
} gnrc_rpl_opt_na_t;

/**
 * @brief RPL-Bloom instance extension
 */
typedef struct {
    struct gnrc_rpl_instance *instance;         /**< RPL instance */
    bloom_t nhood_bloom;                        /**< neighborhood bloom filter */
    bloom_t blacklist_bloom;                    /**< neighborhood bloom filter */
    uint8_t bloom_buf[GNRC_RPL_BLOOM_SIZE/8];   /**< buffer for the bloom filter */
    uint8_t blacklist_bloom_buf[GNRC_RPL_BLOOM_SIZE/8];   /**< buffer for the bloom filter */
    uint8_t dio_send_numof;                     /**< number of DIOs sent */
    bool linksym_check_req;                     /**< link symmetry check request flag */
    bool bloom_fire;                            /**< flag to signal that bloom is refreshing */
    uint32_t bloom_refreshed_at;                /**< time when bloom filter was last refreshed */
} gnrc_rpl_bloom_inst_ext_t;

/**
 * @brief RPL-Bloom parent extension
 */
typedef struct {
    struct gnrc_rpl_parent *parent;             /**< RPL parent */
    bloom_t nhood_bloom;                        /**< neighborhood bloom filter */
    uint8_t bloom_buf[GNRC_RPL_BLOOM_SIZE/8];   /**< buffer for the bloom filter */
    uint8_t linksym_checks_req;                 /**< number of link symmetry checks requested */
} gnrc_rpl_bloom_parent_ext_t;

/**
 * @brief   Add the host suffix of @p src to the neighborhood bloom filter of the @p instance
 *          if the announced parent matches any of the configured addresses
 *
 * @param[in] instance      Pointer to the instance
 * @param[in] src           IPv6 address of the sender
 * @param[in] pa            Parent Announcement
 *
 * @return true, if the announced parent address matches any of the configured addresses
 * @return false, otherwise
 */
bool gnrc_rpl_bloom_add_neighbor(gnrc_rpl_bloom_inst_ext_t *ext, ipv6_addr_t *src,
                                 gnrc_rpl_opt_pa_t *pa);

/**
 * @brief   Initialize the neighborhood bloom filter of an instance
 *
 * @param[in] ext       Pointer to the instance rpl bloom extension
 */
void gnrc_rpl_bloom_instance_nhood_init(gnrc_rpl_bloom_inst_ext_t *ext);

/**
 * @brief   Initialize the neighborhood bloom filter of a parent
 *
 * @param[in] ext       Pointer to the parent rpl bloom extension
 */
void gnrc_rpl_bloom_parent_nhood_init(gnrc_rpl_bloom_parent_ext_t *ext);

/**
 * @brief   Modify the rank according to the link directionality.
 *          Set the MSB of the rank if the link is unidirectional or unchecked.
 *          Set the MSB of the rank if the link is bidrectional
 *
 * @param[in] parent        Pointer to the RPL-Bloom parent extension
 */
void gnrc_rpl_bloom_modify_rank(gnrc_rpl_bloom_parent_ext_t *ext);

#ifdef __cplusplus
}
#endif

#endif /* GNRC_RPL_BLOOM_H_ */
/**
 * @}
 */
