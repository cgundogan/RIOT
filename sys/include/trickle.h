/*
 * Trickle constants and prototypes
 *
 * Copyright (C) 2013, 2014  INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup sys_trickle Trickle Timer
 * @ingroup sys
 * @{
 */

/**
 * @file    trickle.h
 * @brief   Implementation of a generic Trickle Algorithm (RFC 6206)
 *
 * @author  Eric Engel <eric.engel@fu-berlin.de>
 * @author  Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#ifndef _TRICKLE_H
#define _TRICKLE_H

#ifdef __cplusplus
 extern "C" {
#endif

#include "vtimer.h"
#include "thread.h"

typedef struct {
    void (*func)(void *);
    void *args;
} trickle_callback_t;

typedef struct {
    uint8_t k;
    uint32_t Imin;
    uint8_t Imax;
    uint32_t I;
    uint32_t t;
    uint16_t c;
    kernel_pid_t pid;
    trickle_callback_t callback;
    uint16_t interval_msg_type;
    timex_t msg_interval_time;
    vtimer_t msg_interval_timer;
    uint16_t callback_msg_type;
    timex_t msg_callback_time;
    vtimer_t msg_callback_timer;
} trickle_t;

void reset_trickletimer(trickle_t *trickle);
void start_trickle(kernel_pid_t pid, trickle_t *trickle, uint16_t interval_msg_type, uint16_t callback_msg_type, uint32_t Imin, uint8_t Imax, uint8_t k);
void stop_trickle(trickle_t *trickle);
void trickle_increment_counter(trickle_t *trickle);
void trickle_interval(trickle_t *trickle);
void trickle_callback(trickle_t *trickle);

#ifdef __cplusplus
}
#endif

#endif /* _TRICKLE_H */
/** @} */
