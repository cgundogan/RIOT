/*
 * Copyright (C) 2015  INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @ingroup     mqtt
 * @{
 *
 * @file        mqtt.c
 * @brief       Implementation of a simple mqtt client. Version 3.1.1
 *              (http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html)
 *
 * @author      Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#include <string.h>
#include "vtimer.h"
#include "mqtt.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define ENABLE_DEBUG (0)
#include "debug.h"

static uint8_t encode_remain_len(uint32_t remain_len, uint32_t *dest) {
    int8_t counter = -1;
    do {
        uint8_t digit = remain_len % 128;
        remain_len = remain_len / 128;
        if (remain_len > 0) {
            digit |= 0x80;
        }
        ((uint8_t *) dest)[counter + 1] = digit;
        counter++;
    } while(remain_len > 0);

    return counter;
}

static uint8_t decode_remain_len(uint32_t remain_len, uint32_t *dest) {
    int8_t counter = -1;
    uint32_t multiplier = 1;
    uint8_t *digit = 0;
    *dest = 0;
    do {
        digit = (((uint8_t *) &remain_len) + counter + 1);
        *dest += (*digit & 127) * multiplier;
        multiplier += 128;
        counter++;
    } while ((*digit & 128) != 0);

    return counter;
}

static inline uint32_t write_string(uint8_t *buf, char *str) {
    uint16_t *len = (uint16_t *) buf;
    *len = htons(strlen(str));
    memcpy((buf + sizeof(uint16_t)), str, strlen(str));
    return sizeof(uint16_t) + strlen(str);
}

uint8_t fill_fixed_header(mqtt_fixed_header_t *fheader, uint8_t control_packet_type, uint8_t dup_flag,
        uint8_t qos_level, uint8_t retain, uint32_t rem_len, uint8_t rem_len_bytes) {
    fheader->packet_type_flags = ((control_packet_type & 0xF) << 4) | ((dup_flag & 1) << 3)
                                    | ((qos_level & 3) << 1) | ((retain & 1) << 0);
    fheader->remaining_length = rem_len;

    return MQTT_FIXED_HEADER_SIZE + rem_len_bytes;
}

uint8_t fill_connect_header(mqtt_connect_header_t *vheader, mqtt_conn_opts_t *options) {
    vheader->protocol_name_length = htons(MQTT_PROTOCOL_NAME_LEN);
    memcpy(vheader->protocol_name, MQTT_PROTOCOL_NAME, sizeof(vheader->protocol_name));
    vheader->protocol_level = MQTT_PROTOCOL_LEVEL;
    vheader->flags = 0x00;
    vheader->flags |= options ? ((options->clean_session & 1) << 1): (1 << 1);
    vheader->flags |= options && options->password ? (1 << 6) : 0;
    vheader->flags |= options && options->user_name ? (1 << 7): 0;
    vheader->keep_alive_timer = options ? htons(options->keep_alive_timer) : htons(0);

    return MQTT_CONNECT_HEADER_SIZE;
}

int fill_publish_header(MQTT_t *mqtt, uint8_t *vheader, mqtt_topic_t *topic, uint8_t qos_level) {
    int l = 0;
    l += write_string(vheader, topic->topic_name);
    if (qos_level != MQTT_QOS_AT_MOST_ONCE) {
        uint16_t *vheader_message_id = (uint16_t *) (vheader + l);
        *vheader_message_id = htons(mqtt->m_id++);
        l += sizeof(uint16_t);
    }
    
    return l;
}

void parse_publish(MQTT_t *mqtt, uint8_t *fheader) {
    uint8_t l = 0;
    uint32_t remaining_len = 0;
    uint8_t remain_bytes = decode_remain_len(*((uint32_t *) &((mqtt_fixed_header_t *)fheader)->remaining_length), &remaining_len);
    l += MQTT_FIXED_HEADER_SIZE + remain_bytes;
    uint16_t *topic_name_len = (uint16_t *) (fheader + l);
    l += sizeof(*topic_name_len);
    char *topic_name = (char *) (fheader + l);
    if (mqtt->subscription != NULL && strncmp(mqtt->subscription->topic_name, topic_name, ntohs(*topic_name_len)) == 0) {
        mqtt->subscription->callback(mqtt->subscription->topic_name, (void *)(fheader + l + ntohs(*topic_name_len)));
    }
}
/**
 * @}
 */

