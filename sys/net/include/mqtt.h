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
 * @file        mqtt.h
 * @brief       Implementation of a simple mqtt client.
 *              Version 3.1.1 (http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html)
 *
 * @author      Cenk Gündoğan <cnkgndgn@gmail.com>
 */
#ifndef MQTT_H
#define MQTT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MQTT_PROTOCOL_NAME          "MQTT"
#define MQTT_PROTOCOL_NAME_LEN      4
#define MQTT_PROTOCOL_LEVEL         4
#define MQTT_BUFFER_SIZE            1024
#define MQTT_FIXED_HEADER_SIZE      (sizeof(mqtt_fixed_header_t))
#define MQTT_PUBACK_HEADER_SIZE     (sizeof(uint16_t))
#define MQTT_PUBACK_SIZE            (FIXED_HEADER_SIZE + PUBACK_HEADER_SIZE)
#define MQTT_CONNECT_HEADER_SIZE    (sizeof(mqtt_connect_header_t))
#define MQTT_CONNACK_HEADER_SIZE    (sizeof(mqtt_connack_header_t))

typedef enum {
    MQTT_TYPE_RESERVED      =   (0x0),
    MQTT_TYPE_CONNECT       =   (0x1),
    MQTT_TYPE_CONNACK       =   (0x2),
    MQTT_TYPE_PUBLISH       =   (0x3),
    MQTT_TYPE_PUBACK        =   (0x4),
    MQTT_TYPE_PUBREC        =   (0x5),
    MQTT_TYPE_PUBREL        =   (0x6),
    MQTT_TYPE_PUBCOMP       =   (0x7),
    MQTT_TYPE_SUBSCRIBE     =   (0x8),
    MQTT_TYPE_SUBACK        =   (0x9),
    MQTT_TYPE_UNSUBSCRIBE   =   (0xA),
    MQTT_TYPE_UNSUBACK      =   (0xB),
    MQTT_TYPE_PINGREQ       =   (0xC),
    MQTT_TYPE_PINGRESP      =   (0xD),
    MQTT_TYPE_DISCONNECT    =   (0xE),
    MQTT_TYPE_RESERVED2     =   (0xF),
} mqtt_control_packet_type_t;

typedef enum {
    MQTT_CONNECT_FLAG_RESEVED           =   (1 << 0),
    MQTT_CONNECT_FLAG_CLEAN_SESSION     =   (1 << 1),
    MQTT_CONNECT_FLAG_WILL_FLAG         =   (1 << 2),
    MQTT_CONNECT_FLAG_WILL_QOS          =   ((1 << 3) | (1 << 4)),
    MQTT_CONNECT_FLAG_WILL_RETAIN       =   (1 << 5),
    MQTT_CONNECT_FLAG_PASSWORD          =   (1 << 6),
    MQTT_CONNECT_FLAG_USERNAME          =   (1 << 7),
} mqtt_connect_flag_t;

typedef enum {
    MQTT_CONN_ACCEPTED               =   (0x0),
    MQTT_CONNREFUSE_PROTOCOL_VER     =   (0x1),
    MQTT_CONNREFUSE_ID_REJECTED      =   (0x2),
    MQTT_CONNREFUSE_SERVER_UNAVAIL   =   (0x3),
    MQTT_CONNREF_BAD_CREDENTIALS     =   (0x4),
    MQTT_CONNREF_NO_AUTH             =   (0x5),
} mqtt_conn_return_code_t;

typedef enum {
    MQTT_QOS_AT_MOST_ONCE   =   (0x0),
    MQTT_QOS_AT_LEAST_ONCE  =   (0x1),
    MQTT_QOS_EXACTLY_ONCE   =   (0x2),
} mqtt_qos_level_t;

typedef struct __attribute__((packed)) {
#define MQTT_SET_CONTROL_PACKET_TYPE(y,x)   (y->packet_type_flags = (y->packet_type_flags & ~(0xF << 4)) | (x << 4))
#define MQTT_SET_FLAGS(y,x)                 (y->packet_type_flags = (y->packet_type_flags & ~(0xF)) | ((x) & 0xF))
    uint8_t packet_type_flags;
    uint8_t remaining_length;
} mqtt_fixed_header_t;

typedef struct __attribute__((packed)) {
    uint16_t protocol_name_length;
    char protocol_name[MQTT_PROTOCOL_NAME_LEN];
    uint8_t protocol_level;
    uint8_t flags;
    uint16_t keep_alive_timer;
} mqtt_connect_header_t;

typedef struct __attribute__((packed)) {
    uint8_t flags;
    uint8_t ret_code;
} mqtt_connack_header_t;

typedef void (*mqtt_callback_t)(char *topic_name, void *);

typedef struct {
    uint16_t len;
    char *topic_name;
    uint8_t qos_level;
    mqtt_callback_t callback;
} mqtt_topic_t;

typedef struct {
    char *user_name;
    char *password;
    uint8_t clean_session;
    uint16_t keep_alive_timer;
} mqtt_conn_opts_t;

typedef struct {
    int fd;
    uint16_t m_id;
    uint8_t buffer[MQTT_BUFFER_SIZE];
    mqtt_topic_t *subscription;
} MQTT_t;

MQTT_t *mqtt_connect(char *client_id, char *host, uint16_t port, mqtt_conn_opts_t *options);

#ifdef __cplusplus
}
#endif

#endif /* MQTT_H */
/**
 * @}
 */

