/*
 * Copyright (C) 2016 Cenk Gündoğan <mail@cgundogan.de>
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
 * @brief       RPL-Bloom data structs and macros
 *
 * Header file, which defines functionalities used by RPL-Bloom.
 *
 * @author      Cenk Gündoğan <mail@cgundogan.de>
 */

#ifndef GNRC_RPL_BlOOM_H_
#define GNRC_RPL_BlOOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "net/gnrc.h"
#include "net/ipv6/addr.h"
#include "bloom.h"
#include "xtimer.h"

/**
 * @name Bloom filter configuration
 * @{
 */
/**
 * @brief Size of the bloom filter in bytes
 */
#define GNRC_RPL_BLOOM_SIZE                 (8)

/**
 * @brief Size of the blacklist bloom filter in bytes
 */
#define GNRC_RPL_BLACKLIST_BLOOM_SIZE       (16)

/**
 * @brief Number of hashes for the bloom filter
 */
#define GNRC_RPL_BLOOM_HASHES_NUMOF         (8)

/**
 * @brief Number of hashes for the blacklist bloom filter
 */
#define GNRC_RPL_BLOOM_BLACKLIST_HASHES_NUMOF   (8)
/** @} */

/**
 * @name RPL-Bloom Control Message Options
 * @{
*/
#define GNRC_RPL_OPT_PARENT_ANNOUNCEMENT    (13)
#define GNRC_RPL_OPT_NHOOD_ANNOUNCEMENT     (14)
/** @} */

/**
 * @name RPL-Bloom Control Message Options lengths
 * @{
 */
/**
 * @brief Length for the Parent Announcement RPL-Bloom DIS control message option
 */
#define GNRC_RPL_OPT_PA_LEN                 (GNRC_RPL_BLOOM_SIZE)

/**
 * @brief Length for the Neighborhood Announcement RPL-Bloom DIO control message option
 */
#define GNRC_RPL_OPT_NA_LEN                 (sizeof(gnrc_rpl_opt_na_t) - sizeof(gnrc_rpl_opt_t))
/** @} */

/**
 * @brief Check interval in micro seconds
 */
#define GNRC_RPL_BLOOM_INTERVAL             (120 * SEC_IN_USEC)

/**
 * @brief MSG type for link symmetry checks
 */
#define GNRC_RPL_BLOOM_MSG_TYPE_LINKSYM     (0x0910)

/**
 * @brief Link symmetry check max retries
 */
#define GNRC_RPL_BLOOM_LINKSYM_RETRIES      (3)

/**
 * @brief Link symmetry check retry interval in sec
 */
#define GNRC_RPL_BLOOM_LINKSYM_RETRY_INTERVAL   (5)

/**
 * @name Bit positions and shifts for gnrc_rpl_dodag_t::dio_opts
 * @{
 */
#define GNRC_RPL_REQ_OPT_NA_SHIFT               (7)
#define GNRC_RPL_REQ_OPT_NA                     (1 << GNRC_RPL_REQ_OPT_NA_SHIFT)
/** @} */

/**
 * @name Bit positions and shifts for gnrc_rpl_dodag_t::dis_opts
 * @{
 */
#define GNRC_RPL_REQ_DIS_OPT_PA_SHIFT           (7)
#define GNRC_RPL_REQ_DIS_OPT_PA                 (1 << GNRC_RPL_REQ_DIS_OPT_PA_SHIFT)
/** @} */

extern bloom_t gnrc_rpl_bloom_blacklist;
extern uint8_t gnrc_rpl_bloom_blacklist_buf[GNRC_RPL_BLACKLIST_BLOOM_SIZE];

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
} gnrc_rpl_opt_na_t;

/**
 * @brief RPL-Bloom instance extension
 */
typedef struct {
    struct gnrc_rpl_instance *instance;         /**< RPL instance */
    bloom_t nhood_bloom;                        /**< neighborhood bloom filter */
    uint8_t nhood_bloom_buf[GNRC_RPL_BLOOM_SIZE];     /**< buffer for neighborhood bloom filter */
    uint8_t request_retry_numof;                /**< number of request retries */
    bool bloom_fire;                            /**< flag to signal that bloom is refreshing */
    uint32_t bloom_refreshed_at;                /**< time when bloom filter was last refreshed */
} gnrc_rpl_bloom_inst_ext_t;

/**
 * @brief RPL-Bloom parent extension
 */
typedef struct {
    struct gnrc_rpl_parent *parent;             /**< RPL parent */
    bloom_t nhood_bloom;                        /**< neighborhood bloom filter */
    uint8_t nhood_bloom_buf[GNRC_RPL_BLOOM_SIZE]; /**< buffer for bloom filter */
    uint8_t linksym_checks;                     /**< number of link symmetry checks requested */
    bool bidirectional;                         /**< bidirectional link to this parent */
    xtimer_t link_check_timer;                  /**< timer for link symmetry checking */
    msg_t link_check_msg;                       /**< msg for link symmetry checking */
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
 * @brief   Initialize the neighborhood bloom extension of an instance
 *
 * @param[in] ext       Pointer to the instance rpl bloom extension
 */
void gnrc_rpl_bloom_instance_ext_init(gnrc_rpl_bloom_inst_ext_t *ext);

/**
 * @brief   Remove the neighborhood bloom extension of an instance
 *
 * @param[in] ext       Pointer to the instance rpl bloom extension
 */
void gnrc_rpl_bloom_instance_ext_remove(gnrc_rpl_bloom_inst_ext_t *ext);

/**
 * @brief   Initialize the parent rpl bloom extension
 *
 * @param[in] ext       Pointer to the parent rpl bloom extension
 */
void gnrc_rpl_bloom_parent_ext_init(gnrc_rpl_bloom_parent_ext_t *ext);

/**
 * @brief   Remove the parent rpl bloom extension
 *
 * @param[in] ext       Pointer to the parent rpl bloom extension
 */
void gnrc_rpl_bloom_parent_ext_remove(gnrc_rpl_bloom_parent_ext_t *ext);

/**
 * @brief   Build a parent announcement DIS option
 *
 * @param[in] pkt       Pointer to the pktsnip_t
 * @param[in] ext       Pointer to the rpl bloom extension for the parent announcement
 * @param[in] dest      Destination IPv6 address of the parent. Can be NULL.
 *
 * @return Pointer to the pktsnip_t including the parent announcement DIS option, on success
 * @return NULL, otherwise
 */
gnrc_pktsnip_t *gnrc_rpl_bloom_dis_pa_build(gnrc_pktsnip_t *pkt, gnrc_rpl_bloom_inst_ext_t *ext,
                                            ipv6_addr_t *dest);

/**
 * @brief   Build a neighborhood announcement DIO option
 *
 * @param[in] pkt       Pointer to the pktsnip_t
 * @param[in] ext       Pointer to the rpl bloom extension for the instance
 *
 * @return Pointer to the pktsnip_t including the neighborhood announcement DIO option, on success
 * @return NULL, otherwise
 */
gnrc_pktsnip_t *gnrc_rpl_bloom_dio_na_build(gnrc_pktsnip_t *pkt, gnrc_rpl_bloom_inst_ext_t *ext);

/**
 * @brief   Operate as leaf node if we have no parent with a bidirectional link,
 *          send a parent announcement and request a neighborhood announcement
 *
 * @param[in] ext       Pointer to the parent rpl bloom extension
 */
void gnrc_rpl_bloom_request_na(gnrc_rpl_bloom_parent_ext_t *ext);

/**
 * @brief   Initializes the rpl bloom implementation
 */
void gnrc_rpl_bloom_init(void);

/**
 * @brief   Handle a parent announcement option
 *
 * @param[in] opt               Pointer to the parent announcement option
 * @param[in] src               Pointer to the source address of the incoming DIS
 * @param[in] inst              Pointer to the rpl instance
 * @param[in,out] included_opts Pointer to the included options
 */
void gnrc_rpl_bloom_handle_pa(gnrc_rpl_opt_pa_t *opt, ipv6_addr_t *src, gnrc_rpl_instance_t *inst,
                              uint32_t *included_opts);

/**
 * @brief   Handle a neighborhood announcement option
 *
 * @param[in] opt               Pointer to the neighborhood announcement option
 * @param[in] src               Pointer to the source address of the incoming DIS
 * @param[in] inst              Pointer to the rpl instance
 * @param[in,out] included_opts Pointer to the included options
 */
void gnrc_rpl_bloom_handle_na(gnrc_rpl_opt_pa_t *opt, ipv6_addr_t *src, gnrc_rpl_instance_t *inst,
                              uint32_t *included_opts);
#ifdef __cplusplus
}
#endif

#endif /* GNRC_RPL_BLOOM_H_ */
/**
 * @}
 */
