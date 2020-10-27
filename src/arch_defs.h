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

/**
 * @brief Standardized event IDs
 */
enum bperf_event_id {
    INST_RETIRED_ANY = 1,
    CPU_CLK_UNHALTED_THREAD,
    CPU_CLK_UNHALTED_REF_TSC,
    LD_BLOCKS_STORE_FORWARD,
    LD_BLOCKS_NO_SR,
    LD_BLOCKS_PARIAL_ADDRESS_ALIAS,
    DTLB_LOAD_MISSES_MISS_CAUSES_A_WALK,
    DTLB_LOAD_MISSES_WALK_COMPLETED_4K,
    DTLB_LOAD_MISSES_WALK_COMPLETED_2M_4M,
    DTLB_LOAD_MISSES_WALK_COMPLETED_1G,
    DTLB_LOAD_MISSES_WALK_COMPLETED,
    DTLB_LOAD_MISSES_WALK_PENDING,
    DTLB_LOAD_MISSES_WALK_ACTIVE,
    DTLB_LOAD_MISSES_STLB_HIT,
    INT_MISC_RECOVERY_CYCLES,
    INT_MISC_CLEAR_RESTEER_CYCLES,
    UOPS_ISSUED_ANY,
    UOPS_ISSUES_STALL_CYCLES,
    UOPS_ISSUED_VECTOR_WIDTH_MISMATCH,
    UOPS_ISSUED_SLOW_LEA,
    ARITH_DIVIDER_ACTIVE,
    L2_RQSTS_DEMAND_DATA_RD_MISS,
    L2_RQSTS_RFO_MISS,
    L2_RQSTS_CODE_RD_MISS,
    L2_RQSTS_ALL_DEMAND_MISS,
    L2_RQSTS_PF_MISS,
    L2_RQSTS_MISS,
    L2_RQSTS_DEMAND_DATA_RD_HIT,
    L2_RQSTS_RFO_HIT,
    L2_RQSTS_CODE_RD_HIT,
    L2_RQSTS_PF_HIT,
    L2_RQSTS_ALL_DEMAND_DATA_RD,
    L2_RQSTS_ALL_RFO,
    L2_RQSTS_ALL_CODE_RD,
    L2_RQSTS_ALL_DEMAND_REFERENCES,
    L2_RQSTS_ALL_PF,
    L2_RQSTS_REFERENCES,
    CORE_POWER_LVL0_TURBO_LICENSE,
    CORE_POWER_LVL1_TURBO_LICENSE,
    CORE_POWER_LVL2_TURBO_LICENSE,
    CORE_POWER_THROTTLE,
    LONGEST_LAT_CACHE_MISS,
    LONGEST_LAT_CACHE_REFERENCE,
    CPU_CLK_UNHALTED_THREAD_P,
    CPU_CLK_UNHALTED_RING0_TRANS,
    CPU_CLK_UNHALTED_REF_XCLK,
    CPU_CLK_UNHALTED_ONE_THREAD_ACTIVE,
    L1D_PEND_MISS_PENDING,
    L1D_PIND_MISS_PENDING_CYCLES,
    L1D_PEND_MISS_FB_FULL,
    DTLB_STORE_MISSES_MISS_CAUSES_A_WALK,
    DTLB_STORE_MISSES_WALK_COMPLETED_4K,
    DTLB_STORE_MISSES_WALK_COMPLETED_2M_4M,
    DTLB_STORE_MISSES_WALK_COMPLETED_1G,
    DTLB_STORE_MISSES_WALK_COMPLETED,
    DTLB_STORE_MISSES_WALK_PENDING,
    DTLB_STORE_MISSES_WALK_ACTIVE,
    DTLB_STORE_MISSES_STLB_HIT,
    LOAD_HIT_PRE_SW_PF,
    EPT_WALK_PENDING,
    L1D_REPLACEMENT,
    TX_MEM_ABORT_CONFLICT,
    TX_MEM_ABORT_CAPACITY,
    TX_MEM_ABORT_HLE_STORE_TO_ELIDED_LOCK,
    TX_MEM_ABORT_HLE_ELISION_BUFFER_NOT_EMPTY,
    TX_MEM_ABORT_HLE_ELISION_BUFFER_MISMATCH,
    TX_MEM_ABORT_HLE_ELISION_BUFFER_UNSUPPORTED_ALIGNMENT,
    TX_MEM_ABORT_HLE_ELISION_BUFFER_FULL,
    TX_EXEC_MISC1,
    TX_EXEC_MISC2,
    TX_EXEC_MISC3,
    TX_EXEC_MISC4,
    TX_EXEC_MISC5,
    RS_EVENTS_EMPTY_CYCLES,
    RS_EVENTS_EMPTY_END,
    OFFCORE_REQUESTS_OUTSTANDING_DEMAND_DATA_RD,
    OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_DATA_RD,
    OFFCORE_REQUESTS_OUTSTANDING_DEMAND_DATA_RD_GE_6,
    OFFCORE_REQUESTS_OUTSTANDING_DEMAND_CODE_RD,
    OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_CODE_RD,
    OFFCORE_REQUESTS_OUTSTANDING_DEMAND_RFO,
    OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_RFO,
    OFFCORE_REQUESTS_OUTSTANDING_ALL_DATA_RD,
    OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DATA_RD,
    OFFCORE_REQUESTS_OUTSTANDING_L3_MISS_DEMAND_DATA_RD,
    OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_L3_MISS_DEMAND_DATA_RD,
    OFFCORE_REQUESTS_OUTSTANDING_L3_MISS_DEMAND_DATA_RD_GE_6,
    IDQ_MITE_UOPS,
    IDQ_MITE_CYCLES,
    IDQ_DSB_UOPS,
    IDQ_DSB_CYCLES,
    IDQ_MS_DSB_CYCLES,
    IDQ_ALL_DSB_CYCLES_4_UOPS,
    IDQ_ALL_DSB_CYCLES_ANY_UOPS,
    IDQ_MS_MITE_UOPS,
    IDQ_ALL_MITE_CYCLES_4_UOPS,
    IDQ_ALL_MITE_CYCLES_ANY_UOPS,
    IDQ_MS_CYCLES,
    IDQ_MS_SWITCHES,
    IDQ_MS_UOPS,
    ICACHE_16B_IFDATA_STALL,
    ICACHE_64B_IFTAG_HIT,
    ICACHE_64B_IFTAG_MISS,
    ICACHE_64B_IFTAG_STALL,
    ITLB_MISSES_MISS_CAUSES_A_WALK,
    ITLB_MISSES_WALK_COMPLETED_4K,
    ITLB_MISSES_WALK_COMPLETED_2M_4M,
    ITLB_MISSES_WALK_COMPLETED_1G,
    ITLB_MISSES_WALK_COMPLETED,
    ITLB_MISSES_WALK_PENDING,
    ITLB_MISSES_WALK_ACTIVE,
    ITLB_MISSES_STLB_HIT,
};

/**
 * @brief Get integer event ID for event name. 0 on failure
 */
enum bperf_event_id bperf_get_event_id(const char *name);

/**
 * @brief Description of an event
 *
 * This is architecture-specific, and should be queried with bperf_get_arch_event.
 * If this is a fixed counter, is_fixed will be true, and the union will have the fixed counter
 * number in fixed_num.
 * If this is a general performance monitoring counter, is_fixed will be false, and information
 * will be provided in the pmc struct
 */
struct bperf_event {
    bool is_fixed; /* Is this a fixed event? */
    union {
        /* Fixed counter number */
        uint32_t fixed_num;
        /* General-purpose counter information */
        struct {
            uint8_t ev_num; /* Event number */
            uint8_t umask;  /* Umask value */
            uint8_t cmask;  /* Cmask value - 0 means nothing fancy going on here */
            bool    inv;    /* Invert flag - false means nothing fancy here, true means set */
            bool    edge;   /* Edge detect flag - false means nothing fancy here, true means set */
        } pmc;
    };
};

/**
 * @brief Get architecture-specific description of event
 */
const struct bperf_event* bperf_get_arch_event(enum bperf_event_id, uint8_t family, uint8_t model);

#endif // __BPERF_ARCH_DEFS_H__
