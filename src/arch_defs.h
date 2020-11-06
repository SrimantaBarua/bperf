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

/* Useful macro for replicated code for each event */
#define __BPERF_DO_FOR_EACH_EVENT \
    __BPERF_PER_EVENT(LD_BLOCKS, STORE_FORWARD) \
    __BPERF_PER_EVENT(LD_BLOCKS, NO_SR) \
    __BPERF_PER_EVENT(LD_BLOCKS_PARIAL, ADDRESS_ALIAS) \
    __BPERF_PER_EVENT(DTLB_LOAD_MISSES, MISS_CAUSES_A_WALK) \
    __BPERF_PER_EVENT(DTLB_LOAD_MISSES, WALK_COMPLETED_4K) \
    __BPERF_PER_EVENT(DTLB_LOAD_MISSES, WALK_COMPLETED_2M_4M) \
    __BPERF_PER_EVENT(DTLB_LOAD_MISSES, WALK_COMPLETED_1G) \
    __BPERF_PER_EVENT(DTLB_LOAD_MISSES, WALK_COMPLETED) \
    __BPERF_PER_EVENT(DTLB_LOAD_MISSES, WALK_PENDING) \
    __BPERF_PER_EVENT(DTLB_LOAD_MISSES, WALK_ACTIVE) \
    __BPERF_PER_EVENT(DTLB_LOAD_MISSES, STLB_HIT) \
    __BPERF_PER_EVENT(INT_MISC, RECOVERY_CYCLES) \
    __BPERF_PER_EVENT(INT_MISC, CLEAR_RESTEER_CYCLES) \
    __BPERF_PER_EVENT(UOPS_ISSUED, ANY) \
    __BPERF_PER_EVENT(UOPS_ISSUES, STALL_CYCLES) \
    __BPERF_PER_EVENT(UOPS_ISSUED, VECTOR_WIDTH_MISMATCH) \
    __BPERF_PER_EVENT(UOPS_ISSUED, SLOW_LEA) \
    __BPERF_PER_EVENT(ARITH, DIVIDER_ACTIVE) \
    __BPERF_PER_EVENT(L2_RQSTS, DEMAND_DATA_RD_MISS) \
    __BPERF_PER_EVENT(L2_RQSTS, RFO_MISS) \
    __BPERF_PER_EVENT(L2_RQSTS, CODE_RD_MISS) \
    __BPERF_PER_EVENT(L2_RQSTS, ALL_DEMAND_MISS) \
    __BPERF_PER_EVENT(L2_RQSTS, PF_MISS) \
    __BPERF_PER_EVENT(L2_RQSTS, MISS) \
    __BPERF_PER_EVENT(L2_RQSTS, DEMAND_DATA_RD_HIT) \
    __BPERF_PER_EVENT(L2_RQSTS, RFO_HIT) \
    __BPERF_PER_EVENT(L2_RQSTS, CODE_RD_HIT) \
    __BPERF_PER_EVENT(L2_RQSTS, PF_HIT) \
    __BPERF_PER_EVENT(L2_RQSTS, ALL_DEMAND_DATA_RD) \
    __BPERF_PER_EVENT(L2_RQSTS, ALL_RFO) \
    __BPERF_PER_EVENT(L2_RQSTS, ALL_CODE_RD) \
    __BPERF_PER_EVENT(L2_RQSTS, ALL_DEMAND_REFERENCES) \
    __BPERF_PER_EVENT(L2_RQSTS, ALL_PF) \
    __BPERF_PER_EVENT(L2_RQSTS, REFERENCES) \
    __BPERF_PER_EVENT(CORE_POWER, LVL0_TURBO_LICENSE) \
    __BPERF_PER_EVENT(CORE_POWER, LVL1_TURBO_LICENSE) \
    __BPERF_PER_EVENT(CORE_POWER, LVL2_TURBO_LICENSE) \
    __BPERF_PER_EVENT(CORE_POWER, THROTTLE) \
    __BPERF_PER_EVENT(LONGEST_LAT_CACHE, MISS) \
    __BPERF_PER_EVENT(LONGEST_LAT_CACHE, REFERENCE) \
    __BPERF_PER_EVENT(CPU_CLK_UNHALTED, THREAD) \
    __BPERF_PER_EVENT(CPU_CLK_UNHALTED, RING0_TRANS) \
    __BPERF_PER_EVENT(CPU_CLK_UNHALTED, REF_TSC) \
    __BPERF_PER_EVENT(CPU_CLK_UNHALTED, ONE_THREAD_ACTIVE) \
    __BPERF_PER_EVENT(L1D_PEND_MISS, PENDING) \
    __BPERF_PER_EVENT(L1D_PIND_MISS, PENDING_CYCLES) \
    __BPERF_PER_EVENT(L1D_PEND_MISS, FB_FULL) \
    __BPERF_PER_EVENT(DTLB_STORE_MISSES, MISS_CAUSES_A_WALK) \
    __BPERF_PER_EVENT(DTLB_STORE_MISSES, WALK_COMPLETED_4K) \
    __BPERF_PER_EVENT(DTLB_STORE_MISSES, WALK_COMPLETED_2M_4M) \
    __BPERF_PER_EVENT(DTLB_STORE_MISSES, WALK_COMPLETED_1G) \
    __BPERF_PER_EVENT(DTLB_STORE_MISSES, WALK_COMPLETED) \
    __BPERF_PER_EVENT(DTLB_STORE_MISSES, WALK_PENDING) \
    __BPERF_PER_EVENT(DTLB_STORE_MISSES, WALK_ACTIVE) \
    __BPERF_PER_EVENT(DTLB_STORE_MISSES, STLB_HIT) \
    __BPERF_PER_EVENT(LOAD_HIT_PRE, SW_PF) \
    __BPERF_PER_EVENT(EPT, WALK_PENDING) \
    __BPERF_PER_EVENT(L1D, REPLACEMENT) \
    __BPERF_PER_EVENT(TX_MEM, ABORT_CONFLICT) \
    __BPERF_PER_EVENT(TX_MEM, ABORT_CAPACITY) \
    __BPERF_PER_EVENT(TX_MEM, ABORT_HLE_STORE_TO_ELIDED_LOCK) \
    __BPERF_PER_EVENT(TX_MEM, ABORT_HLE_ELISION_BUFFER_NOT_EMPTY) \
    __BPERF_PER_EVENT(TX_MEM, ABORT_HLE_ELISION_BUFFER_MISMATCH) \
    __BPERF_PER_EVENT(TX_MEM, ABORT_HLE_ELISION_BUFFER_UNSUPPORTED_ALIGNMENT) \
    __BPERF_PER_EVENT(TX_MEM, ABORT_HLE_ELISION_BUFFER_FULL) \
    __BPERF_PER_EVENT(TX_EXEC, MISC1) \
    __BPERF_PER_EVENT(TX_EXEC, MISC2) \
    __BPERF_PER_EVENT(TX_EXEC, MISC3) \
    __BPERF_PER_EVENT(TX_EXEC, MISC4) \
    __BPERF_PER_EVENT(TX_EXEC, MISC5) \
    __BPERF_PER_EVENT(RS_EVENTS, EMPTY_CYCLES) \
    __BPERF_PER_EVENT(RS_EVENTS, EMPTY_END) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, DEMAND_DATA_RD) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_DEMAND_DATA_RD) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, DEMAND_DATA_RD_GE_6) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, DEMAND_CODE_RD) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_DEMAND_CODE_RD) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, DEMAND_RFO) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_DEMAND_RFO) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, ALL_DATA_RD) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_DATA_RD) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, L3_MISS_DEMAND_DATA_RD) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_L3_MISS_DEMAND_DATA_RD) \
    __BPERF_PER_EVENT(OFFCORE_REQUESTS_OUTSTANDING, L3_MISS_DEMAND_DATA_RD_GE_6) \
    __BPERF_PER_EVENT(IDQ, MITE_UOPS) \
    __BPERF_PER_EVENT(IDQ, MITE_CYCLES) \
    __BPERF_PER_EVENT(IDQ, DSB_UOPS) \
    __BPERF_PER_EVENT(IDQ, DSB_CYCLES) \
    __BPERF_PER_EVENT(IDQ, MS_DSB_CYCLES) \
    __BPERF_PER_EVENT(IDQ, ALL_DSB_CYCLES_4_UOPS) \
    __BPERF_PER_EVENT(IDQ, ALL_DSB_CYCLES_ANY_UOPS) \
    __BPERF_PER_EVENT(IDQ, MS_MITE_UOPS) \
    __BPERF_PER_EVENT(IDQ, ALL_MITE_CYCLES_4_UOPS) \
    __BPERF_PER_EVENT(IDQ, ALL_MITE_CYCLES_ANY_UOPS) \
    __BPERF_PER_EVENT(IDQ, MS_CYCLES) \
    __BPERF_PER_EVENT(IDQ, MS_SWITCHES) \
    __BPERF_PER_EVENT(IDQ, MS_UOPS) \
    __BPERF_PER_EVENT(ICACHE_16B, IFDATA_STALL) \
    __BPERF_PER_EVENT(ICACHE_64B, IFTAG_HIT) \
    __BPERF_PER_EVENT(ICACHE_64B, IFTAG_MISS) \
    __BPERF_PER_EVENT(ICACHE_64B, IFTAG_STALL) \
    __BPERF_PER_EVENT(ITLB_MISSES, MISS_CAUSES_A_WALK) \
    __BPERF_PER_EVENT(ITLB_MISSES, WALK_COMPLETED_4K) \
    __BPERF_PER_EVENT(ITLB_MISSES, WALK_COMPLETED_2M_4M) \
    __BPERF_PER_EVENT(ITLB_MISSES, WALK_COMPLETED_1G) \
    __BPERF_PER_EVENT(ITLB_MISSES, WALK_COMPLETED) \
    __BPERF_PER_EVENT(ITLB_MISSES, WALK_PENDING) \
    __BPERF_PER_EVENT(ITLB_MISSES, WALK_ACTIVE) \
    __BPERF_PER_EVENT(ITLB_MISSES, STLB_HIT)
//__BPERF_PER_EVENT(INST_RETIRED, ANY)
/* TODO: Add more events */

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
