/**
 * @file    arch_defs.h
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    25 October 2020
 * @version 0.1
 * @brief   Interface for architecture-specific counter definitions
 */

#ifndef __BPERF_ARCH_DEFS_H__
#define __BPERF_ARCH_DEFS_H__

#include <linux/types.h>
#include "arch_def_macro.h"

/**
 * @brief Standardized event IDs
 */
enum bperf_event_id {
    DISABLED = 0,
#define __BPERF_PER_EVENT(x, y) x ## _ ## y ,
    __BPERF_DO_FOR_EACH_EVENT
#undef __BPERF_PER_EVENT
    __UNKNOWN_EVENT__,
};

/**
 * @brief Get name for fixed counter
 */
const char* bperf_get_fixed_ctr_name(size_t i);

/**
 * @brief Get integer event ID for event name. 0 on failure
 */
enum bperf_event_id bperf_get_event_id(const char *name, size_t len);

/**
 * @brief Get string name for event ID
 */
const char* bperf_get_event_name(enum bperf_event_id id);

/**
 * @brief Description of an event
 *
 * This is architecture-specific, and should be queried with bperf_get_arch_event.
 */
struct bperf_event {
    uint8_t ev_num; /* Event number */
    uint8_t umask;  /* Umask value */
    uint8_t cmask;  /* Cmask value - 0 means nothing fancy going on here */
    bool    inv;    /* Invert flag - false means nothing fancy here, true means set */
    bool    edge;   /* Edge detect flag - false means nothing fancy here, true means set */
};

/**
 * @brief Get architecture-specific description of event
 */
const struct bperf_event* bperf_get_arch_event(enum bperf_event_id, uint8_t family, uint8_t model);

#endif // __BPERF_ARCH_DEFS_H__
