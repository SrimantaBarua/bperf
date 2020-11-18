/**
 * @file    arch_defs.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    25 October 2020
 * @version 0.1
 * @brief   Architecture-specific counter definitions
 */


#include <linux/string.h>
#include "arch_defs.h"

/**
 * @brief Get name for fixed counter
 */
const char* bperf_get_fixed_ctr_name(size_t i) {
    switch (i) {
    case 0:  return "INST_RETIRED.ANY";
    case 1:  return "CPU_CLK_UNHALTED.THREAD";
    case 2:  return "CPU_CLK_UNHALTED.REF_TSC";
    default: return "__UNKNOWN_EVENT__";
    }
}

/**
 * @brief Get integer event ID for event name. 0 on failure
 */
enum bperf_event_id bperf_get_event_id(const char *name, size_t len)
{
#define __BPERF_PER_EVENT(x, y) do { \
    if (!strncmp(name, #x "." #y, len)) { \
        return x ## _ ## y; \
    } \
} while (0);
    __BPERF_DO_FOR_EACH_EVENT
#undef __BPERF_PER_EVENT
    if (!strncmp(name, "DISABLED", len)) {
        return DISABLED;
    }
    return __UNKNOWN_EVENT__;
}

const char* bperf_get_event_name(enum bperf_event_id id)
{
#define __BPERF_PER_EVENT(x, y) case x ## _ ## y : return #x "." #y;
    switch (id) {
        case DISABLED: return "DISABLED";
        __BPERF_DO_FOR_EACH_EVENT
        default: return "__UNKNOWN_EVENT__";
    }
#undef __BPERF_PER_EVENT
}

/**
 * @brief A tuple of standardized event number, and information
 */
struct bperf_event_tuple {
    enum bperf_event_id id; /* Standardized event ID */
    struct bperf_event  ev; /* Event information struct */
};

/**
 * @brief A tuple for arch-specific events
 */
struct bperf_arch_events {
    uint8_t                  family;  /* DisplayFamily */
    uint8_t                  model;   /* DisplayModel */
    struct bperf_event_tuple *events; /* List of events, terminated by event_id = 0 */
};

// Helper macros for static event definitions
#define PMC(ev, um)                   { .ev_num = ev, .umask = um, .cmask = 0,  .inv = false, .edge = false }
#define PMC_CMASK(ev, um, cm)         { .ev_num = ev, .umask = um, .cmask = cm, .inv = false, .edge = false }
#define PMC_EDG(ev, um)               { .ev_num = ev, .umask = um, .cmask = 0, .inv = false, .edge = true }
#define PMC_CMASK_INV(ev, um, cm)     { .ev_num = ev, .umask = um, .cmask = cm, .inv = true, .edge = false }
#define PMC_CMASK_EDG(ev, um, cm)     { .ev_num = ev, .umask = um, .cmask = cm, .inv = false, .edge = true }
#define PMC_CMASK_INV_EDG(ev, um, cm) { .ev_num = ev, .umask = um, .cmask = cm, .inv = true, .edge = true }

/* Event definitions for 06_55 */
static struct bperf_event_tuple EVENTS_06_55[] = {
    { LD_BLOCKS_STORE_FORWARD,                                          PMC(0x03, 0x02) },
    { LD_BLOCKS_NO_SR,                                                  PMC(0x03, 0x08) },
    { LD_BLOCKS_PARIAL_ADDRESS_ALIAS,                                   PMC(0x07, 0x01) },
    { DTLB_LOAD_MISSES_MISS_CAUSES_A_WALK,                              PMC(0x08, 0x01) },
    { DTLB_LOAD_MISSES_WALK_COMPLETED_4K,                               PMC(0x08, 0x02) },
    { DTLB_LOAD_MISSES_WALK_COMPLETED_2M_4M,                            PMC(0x08, 0x04) },
    { DTLB_LOAD_MISSES_WALK_COMPLETED_1G,                               PMC(0x08, 0x08) },
    { DTLB_LOAD_MISSES_WALK_COMPLETED,                                  PMC(0x08, 0x0e) },
    { DTLB_LOAD_MISSES_WALK_PENDING,                                    PMC(0x08, 0x10) },
    { DTLB_LOAD_MISSES_WALK_ACTIVE,                                     PMC_CMASK(0x08, 0x10, 1) },
    { DTLB_LOAD_MISSES_STLB_HIT,                                        PMC(0x08, 0x20) },
    { INT_MISC_RECOVERY_CYCLES,                                         PMC(0x0d, 0x01) },
    { INT_MISC_CLEAR_RESTEER_CYCLES,                                    PMC(0x0d, 0x80) },
    { UOPS_ISSUED_ANY,                                                  PMC(0x0e, 0x01) },
    { UOPS_ISSUES_STALL_CYCLES,                                         PMC_CMASK_INV(0x0e, 0x01, 1) },
    { UOPS_ISSUED_VECTOR_WIDTH_MISMATCH,                                PMC(0x0e, 0x02) },
    { UOPS_ISSUED_SLOW_LEA,                                             PMC(0x0e, 0x20) },
    { ARITH_DIVIDER_ACTIVE,                                             PMC_CMASK(0x14, 0x01, 1) },
    { L2_RQSTS_DEMAND_DATA_RD_MISS,                                     PMC(0x24, 0x21) },
    { L2_RQSTS_RFO_MISS,                                                PMC(0x24, 0x22) },
    { L2_RQSTS_CODE_RD_MISS,                                            PMC(0x24, 0x24) },
    { L2_RQSTS_ALL_DEMAND_MISS,                                         PMC(0x24, 0x27) },
    { L2_RQSTS_PF_MISS,                                                 PMC(0x24, 0x38) },
    { L2_RQSTS_MISS,                                                    PMC(0x24, 0x3f) },
    { L2_RQSTS_DEMAND_DATA_RD_HIT,                                      PMC(0x24, 0x41) },
    { L2_RQSTS_RFO_HIT,                                                 PMC(0x24, 0x42) },
    { L2_RQSTS_CODE_RD_HIT,                                             PMC(0x24, 0x44) },
    { L2_RQSTS_PF_HIT,                                                  PMC(0x24, 0xd8) },
    { L2_RQSTS_ALL_DEMAND_DATA_RD,                                      PMC(0x24, 0xe1) },
    { L2_RQSTS_ALL_RFO,                                                 PMC(0x24, 0xe2) },
    { L2_RQSTS_ALL_CODE_RD,                                             PMC(0x24, 0xe4) },
    { L2_RQSTS_ALL_DEMAND_REFERENCES,                                   PMC(0x24, 0xe7) },
    { L2_RQSTS_ALL_PF,                                                  PMC(0x24, 0xf8) },
    { L2_RQSTS_REFERENCES,                                              PMC(0x24, 0xff) },
    { CORE_POWER_LVL0_TURBO_LICENSE,                                    PMC(0x28, 0x07) },
    { CORE_POWER_LVL1_TURBO_LICENSE,                                    PMC(0x28, 0x18) },
    { CORE_POWER_LVL2_TURBO_LICENSE,                                    PMC(0x28, 0x20) },
    { CORE_POWER_THROTTLE,                                              PMC(0x28, 0x40) },
    { LONGEST_LAT_CACHE_MISS,                                           PMC(0x2e, 0x41) },
    { LONGEST_LAT_CACHE_REFERENCE,                                      PMC(0x2e, 0x4f) },
    { CPU_CLK_UNHALTED_THREAD,                                          PMC(0x3c, 0x00) },
    { CPU_CLK_UNHALTED_RING0_TRANS,                                     PMC_CMASK_EDG(0x3c, 0x00, 1) },
    { CPU_CLK_UNHALTED_REF_TSC,                                         PMC(0x3c, 0x01) },
    { CPU_CLK_UNHALTED_ONE_THREAD_ACTIVE,                               PMC(0x3c, 0x02) },
    { L1D_PEND_MISS_PENDING,                                            PMC(0x48, 0x01) },
    { L1D_PIND_MISS_PENDING_CYCLES,                                     PMC_CMASK(0x48, 0x01, 1) },
    { L1D_PEND_MISS_FB_FULL,                                            PMC(0x48, 0x02) },
    { DTLB_STORE_MISSES_MISS_CAUSES_A_WALK,                             PMC(0x49, 0x01) },
    { DTLB_STORE_MISSES_WALK_COMPLETED_4K,                              PMC(0x49, 0x02) },
    { DTLB_STORE_MISSES_WALK_COMPLETED_2M_4M,                           PMC(0x49, 0x04) },
    { DTLB_STORE_MISSES_WALK_COMPLETED_1G,                              PMC(0x49, 0x08) },
    { DTLB_STORE_MISSES_WALK_COMPLETED,                                 PMC(0x49, 0x0e) },
    { DTLB_STORE_MISSES_WALK_PENDING,                                   PMC(0x49, 0x10) },
    { DTLB_STORE_MISSES_WALK_ACTIVE,                                    PMC_CMASK(0x49, 0x10, 1) },
    { DTLB_STORE_MISSES_STLB_HIT,                                       PMC(0x49, 0x20) },
    { LOAD_HIT_PRE_SW_PF,                                               PMC(0x4c, 0x01) },
    { EPT_WALK_PENDING,                                                 PMC(0x4f, 0x10) },
    { L1D_REPLACEMENT,                                                  PMC(0x51, 0x01) },
    { TX_MEM_ABORT_CONFLICT,                                            PMC(0x54, 0x01) },
    { TX_MEM_ABORT_CAPACITY,                                            PMC(0x54, 0x02) },
    { TX_MEM_ABORT_HLE_STORE_TO_ELIDED_LOCK,                            PMC(0x54, 0x04) },
    { TX_MEM_ABORT_HLE_ELISION_BUFFER_NOT_EMPTY,                        PMC(0x54, 0x08) },
    { TX_MEM_ABORT_HLE_ELISION_BUFFER_MISMATCH,                         PMC(0x54, 0x10) },
    { TX_MEM_ABORT_HLE_ELISION_BUFFER_UNSUPPORTED_ALIGNMENT,            PMC(0x54, 0x20) },
    { TX_MEM_ABORT_HLE_ELISION_BUFFER_FULL,                             PMC(0x54, 0x40) },
    { TX_EXEC_MISC1,                                                    PMC(0x5d, 0x01) },
    { TX_EXEC_MISC2,                                                    PMC(0x5d, 0x02) },
    { TX_EXEC_MISC3,                                                    PMC(0x5d, 0x04) },
    { TX_EXEC_MISC4,                                                    PMC(0x5d, 0x08) },
    { TX_EXEC_MISC5,                                                    PMC(0x5d, 0x10) },
    { RS_EVENTS_EMPTY_CYCLES,                                           PMC(0x5e, 0x01) },
    { RS_EVENTS_EMPTY_END,                                              PMC_CMASK_INV_EDG(0x5e, 0x01, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_DEMAND_DATA_RD,                      PMC(0x60, 0x01) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_DATA_RD,          PMC_CMASK(0x60, 0x01, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_DEMAND_DATA_RD_GE_6,                 PMC_CMASK(0x60, 0x01, 6) },
    { OFFCORE_REQUESTS_OUTSTANDING_DEMAND_CODE_RD,                      PMC_CMASK(0x60, 0x02, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_CODE_RD,          PMC_CMASK(0x60, 0x02, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_DEMAND_RFO,                          PMC_CMASK(0x60, 0x04, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_RFO,              PMC_CMASK(0x60, 0x04, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_ALL_DATA_RD,                         PMC(0x60, 0x08) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DATA_RD,                 PMC_CMASK(0x60, 0x08, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_L3_MISS_DEMAND_DATA_RD,              PMC(0x60, 0x10) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_L3_MISS_DEMAND_DATA_RD,  PMC_CMASK(0x60, 0x10, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_L3_MISS_DEMAND_DATA_RD_GE_6,         PMC_CMASK(0x60, 0x10, 6) },
    { IDQ_MITE_UOPS,                                                    PMC(0x79, 0x04) },
    { IDQ_MITE_CYCLES,                                                  PMC_CMASK(0x79, 0x04, 1) },
    { IDQ_DSB_UOPS,                                                     PMC(0x79, 0x08) },
    { IDQ_DSB_CYCLES,                                                   PMC_CMASK(0x79, 0x08, 1) },
    { IDQ_MS_DSB_CYCLES,                                                PMC_CMASK(0x79, 0x10, 1) },
    { IDQ_ALL_DSB_CYCLES_ANY_UOPS,                                      PMC_CMASK(0x79, 0x18, 1) },
    { IDQ_ALL_DSB_CYCLES_4_UOPS,                                        PMC_CMASK(0x79, 0x18, 4) },
    { IDQ_MS_MITE_UOPS,                                                 PMC(0x79, 0x20) },
    { IDQ_ALL_MITE_CYCLES_ANY_UOPS,                                     PMC_CMASK(0x79, 0x24, 1) },
    { IDQ_ALL_MITE_CYCLES_4_UOPS,                                       PMC_CMASK(0x79, 0x24, 4) },
    { IDQ_MS_CYCLES,                                                    PMC_CMASK(0x79, 0x30, 1) },
    { IDQ_MS_SWITCHES,                                                  PMC_CMASK_EDG(0x79, 0x30, 1) },
    { IDQ_MS_UOPS,                                                      PMC(0x79, 0x30) },
    { ICACHE_16B_IFDATA_STALL,                                          PMC(0x80, 0x04) },
    { ICACHE_64B_IFTAG_HIT,                                             PMC(0x83, 0x01) },
    { ICACHE_64B_IFTAG_MISS,                                            PMC(0x83, 0x02) },
    { ICACHE_64B_IFTAG_STALL,                                           PMC(0x83, 0x04) },
    { ITLB_MISSES_MISS_CAUSES_A_WALK,                                   PMC(0x85, 0x01) },
    { ITLB_MISSES_WALK_COMPLETED_4K,                                    PMC(0x85, 0x02) },
    { ITLB_MISSES_WALK_COMPLETED_2M_4M,                                 PMC(0x85, 0x04) },
    { ITLB_MISSES_WALK_COMPLETED_1G,                                    PMC(0x85, 0x08) },
    { ITLB_MISSES_WALK_COMPLETED,                                       PMC(0x85, 0x0e) },
    { ITLB_MISSES_WALK_PENDING,                                         PMC(0x85, 0x10) },
    { ITLB_MISSES_WALK_ACTIVE,                                          PMC_CMASK(0x85, 0x10, 1) },
    { ITLB_MISSES_STLB_HIT,                                             PMC(0x85, 0x20) },
    { ILD_STALL_LCP,                                                    PMC(0x87, 0x01) },
    { IDQ_UOPS_NOT_DELIVERED_CORE,                                      PMC(0x9c, 0x01) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_0_UOP_DELIV_CORE,                   PMC_CMASK(0x9c, 0x01, 4) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_LE_1_UOP_DELIV_CORE,                PMC_CMASK(0x9c, 0x01, 3) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_LE_2_UOP_DELIV_CORE,                PMC_CMASK(0x9c, 0x01, 2) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_LE_3_UOP_DELIV_CORE,                PMC_CMASK(0x9c, 0x01, 1) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_FE_WAS_OK,                          PMC_CMASK_INV(0x9c, 0x01, 1) },
    { UOPS_DISPATCHED_PORT_PORT_0,                                      PMC(0xa1, 0x01) },
    { UOPS_DISPATCHED_PORT_PORT_1,                                      PMC(0xa1, 0x02) },
    { UOPS_DISPATCHED_PORT_PORT_2,                                      PMC(0xa1, 0x04) },
    { UOPS_DISPATCHED_PORT_PORT_3,                                      PMC(0xa1, 0x08) },
    { UOPS_DISPATCHED_PORT_PORT_4,                                      PMC(0xa1, 0x10) },
    { UOPS_DISPATCHED_PORT_PORT_5,                                      PMC(0xa1, 0x20) },
    { UOPS_DISPATCHED_PORT_PORT_6,                                      PMC(0xa1, 0x40) },
    { UOPS_DISPATCHED_PORT_PORT_7,                                      PMC(0xa1, 0x80) },
    { RESOURCE_STALLS_ANY,                                              PMC(0xa2, 0x01) },
    { RESOURCE_STALLS_SB,                                               PMC(0xa2, 0x08) },
    { CYCLE_ACTIVITY_CYCLES_L2_MISS,                                    PMC(0xa3, 0x01) },
    { CYCLE_ACTIVITY_CYCLES_L3_MISS,                                    PMC(0xa3, 0x02) },
    { CYCLE_ACTIVITY_STALLS_TOTAL,                                      PMC(0xa3, 0x04) },
    { CYCLE_ACTIVITY_STALLS_L2_MISS,                                    PMC(0xa3, 0x05) },
    { CYCLE_ACTIVITY_STALLS_L3_MISS,                                    PMC(0xa3, 0x06) },
    { CYCLE_ACTIVITY_CYCLES_L1D_MISS,                                   PMC(0xa3, 0x08) },
    { CYCLE_ACTIVITY_STALLS_L1D_MISS,                                   PMC(0xa3, 0x0c) },
    { CYCLE_ACTIVITY_CYCLES_MEM_ANY,                                    PMC(0xa3, 0x10) },
    { CYCLE_ACTIVITY_STALLS_MEM_ANY,                                    PMC(0xa3, 0x14) },
    { EXE_ACTIVITY_BOUND_0_PORTS,                                       PMC(0xa6, 0x01) },
    { EXE_ACTIVITY_1_PORTS_UTIL,                                        PMC(0xa6, 0x02) },
    { EXE_ACTIVITY_2_PORTS_UTIL,                                        PMC(0xa6, 0x04) },
    { EXE_ACTIVITY_3_PORTS_UTIL,                                        PMC(0xa6, 0x08) },
    { EXE_ACTIVITY_4_PORTS_UTIL,                                        PMC(0xa6, 0x10) },
    { EXE_ACTIVITY_BOUND_ON_STORES,                                     PMC(0xa6, 0x40) },
    { LSD_UOPS,                                                         PMC(0xa8, 0x01) },
    { LSD_CYCLES_ACTIVE,                                                PMC_CMASK(0xa8, 0x01, 1) },
    { LSD_CYCLES_4_UOPS,                                                PMC_CMASK(0xa8, 0x01, 4) },
    { DSB2MITE_SWITCHES_PENALTY_CYCLES,                                 PMC(0xab, 0x02) },
    { ITLB_ITLB_FLUSH,                                                  PMC(0xae, 0x01) },
    { OFFCORE_REQUESTS_DEMAND_DATA_RD,                                  PMC(0xb0, 0x01) },
    { OFFCORE_REQUESTS_DEMAND_CODE_RD,                                  PMC(0xb0, 0x02) },
    { OFFCORE_REQUESTS_DEMAND_RFO,                                      PMC(0xb0, 0x04) },
    { OFFCORE_REQUESTS_ALL_DATA_RD,                                     PMC(0xb0, 0x08) },
    { OFFCORE_REQUESTS_L3_MISS_DEMAND_DATA_RD,                          PMC(0xb0, 0x10) },
    { OFFCORE_REQUESTS_ALL_REQUESTS,                                    PMC(0xb0, 0x80) },
    { UOPS_EXECUTED_THREAD,                                             PMC(0xb1, 0x01) },
    { UOPS_EXECUTED_STALL_CYCLES,                                       PMC_CMASK_INV(0xb1, 0x01, 1) },
    { UOPS_EXECUTED_CYCLES_GE_1_UOP_EXEC,                               PMC_CMASK(0xb1, 0x01, 1) },
    { UOPS_EXECUTED_CYCLES_GE_2_UOP_EXEC,                               PMC_CMASK(0xb1, 0x01, 2) },
    { UOPS_EXECUTED_CYCLES_GE_3_UOP_EXEC,                               PMC_CMASK(0xb1, 0x01, 3) },
    { UOPS_EXECUTED_CYCLES_GE_4_UOP_EXEC,                               PMC_CMASK(0xb1, 0x01, 4) },
    { UOPS_EXECUTED_CORE,                                               PMC(0xb1, 0x02) },
    { UOPS_EXECUTED_CORE_CYCLES_GE_1,                                   PMC_CMASK(0xb1, 0x02, 1) },
    { UOPS_EXECUTED_CORE_CYCLES_GE_2,                                   PMC_CMASK(0xb1, 0x02, 2) },
    { UOPS_EXECUTED_CORE_CYCLES_GE_3,                                   PMC_CMASK(0xb1, 0x02, 3) },
    { UOPS_EXECUTED_CORE_CYCLES_GE_4,                                   PMC_CMASK(0xb1, 0x02, 4) },
    { UOPS_EXECUTED_CORE_CYCLES_NONE,                                   PMC_CMASK_INV(0xb1, 0x02, 1) },
    { UOPS_EXECUTED_X87,                                                PMC(0xb1, 0x10) },
    { OFF_CORE_REQUEST_BUFFER_SQ_FULL,                                  PMC(0xb2, 0x01) },
    { TLB_FLUSH_DTLB_THREAD,                                            PMC(0xbd, 0x01) },
    { TLB_FLUSH_STLB_ANY,                                               PMC(0xbd, 0x20) },
    { INST_RETIRED_ANY,                                                 PMC(0xc0, 0x00) },
    { OTHER_ASSISTS_ANY,                                                PMC(0xc1, 0x3f) },
    { UOPS_RETIRED_STALL_CYCLES,                                        PMC_CMASK_INV(0xc2, 0x01, 1) },
    { UOPS_RETIRED_TOTAL_CYCLES,                                        PMC_CMASK_INV(0xc2, 0x01, 10) },
    { UOPS_RETIRED_RETIRE_SLOTS,                                        PMC(0xc2, 0x02) },
    { MACHINE_CLEARS_COUNT,                                             PMC(0xc3, 0x01) },
    { MACHINE_CLEARS_MEMORY_ORDERING,                                   PMC(0xc3, 0x02) },
    { MACHINE_CLEARS_SMC,                                               PMC(0xc3, 0x04) },
    { BR_INST_RETIRED_ALL_BRANCHES,                                     PMC(0xc4, 0x00) },
    { BR_INST_RETIRED_CONDITIONAL,                                      PMC(0xc4, 0x01) },
    { BR_INST_RETIRED_NEAR_CALL,                                        PMC(0xc4, 0x02) },
    { BR_INST_RETIRED_NEAR_RETURN,                                      PMC(0xc4, 0x08) },
    { BR_INST_RETIRED_NOT_TAKEN,                                        PMC(0xc4, 0x10) },
    { BR_INST_RETIRED_NEAR_TAKEN,                                       PMC(0xc4, 0x20) },
    { BR_INST_RETIRED_FAR_BRANCH,                                       PMC(0xc4, 0x40) },
    { BR_MISP_RETIRED_ALL_BRANCHES,                                     PMC(0xc5, 0x00) },
    { BR_MISP_RETIRED_CONDITIONAL,                                      PMC(0xc5, 0x01) },
    { BR_MISP_RETIRED_NEAR_CALL,                                        PMC(0xc5, 0x02) },
    { BR_MISP_RETIRED_NEAR_TAKEN,                                       PMC(0xc5, 0x20) },
    { FP_ARITH_INST_RETIRED_SCALAR_DOUBLE,                              PMC(0xc7, 0x01) },
    { FP_ARITH_INST_RETIRED_SCALAR_SINGLE,                              PMC(0xc7, 0x02) },
    { FP_ARITH_INST_RETIRED_128B_PACKED_DOUBLE,                         PMC(0xc7, 0x04) },
    { FP_ARITH_INST_RETIRED_128B_PACKED_SINGLE,                         PMC(0xc7, 0x08) },
    { FP_ARITH_INST_RETIRED_256B_PACKED_DOUBLE,                         PMC(0xc7, 0x10) },
    { FP_ARITH_INST_RETIRED_256B_PACKED_SINGLE,                         PMC(0xc7, 0x20) },
    { FP_ARITH_INST_RETIRED_512B_PACKED_DOUBLE,                         PMC(0xc7, 0x40) },
    { FP_ARITH_INST_RETIRED_512B_PACKED_SINGLE,                         PMC(0xc7, 0x80) },
    { HLE_RETIRED_START,                                                PMC(0xc8, 0x01) },
    { HLE_RETIRED_COMMIT,                                               PMC(0xc8, 0x02) },
    { HLE_RETIRED_ABORTED,                                              PMC(0xc8, 0x04) },
    { HLE_RETIRED_ABORTED_MEM,                                          PMC(0xc8, 0x08) },
    { HLE_RETIRED_ABORTED_TIMER,                                        PMC(0xc8, 0x10) },
    { HLE_RETIRED_ABORTED_UNFRIENDLY,                                   PMC(0xc8, 0x20) },
    { HLE_RETIRED_ABORTED_MEMTYPE,                                      PMC(0xc8, 0x40) },
    { HLE_RETIRED_ABORTED_EVENTS,                                       PMC(0xc8, 0x80) },
    { RTM_RETIRED_START,                                                PMC(0xc9, 0x01) },
    { RTM_RETIRED_COMMIT,                                               PMC(0xc9, 0x02) },
    { RTM_RETIRED_ABORTED,                                              PMC(0xc9, 0x04) },
    { RTM_RETIRED_ABORTED_MEM,                                          PMC(0xc9, 0x08) },
    { RTM_RETIRED_ABORTED_TIMER,                                        PMC(0xc9, 0x10) },
    { RTM_RETIRED_ABORTED_UNFRIENDLY,                                   PMC(0xc9, 0x20) },
    { RTM_RETIRED_ABORTED_MEMTYPE,                                      PMC(0xc9, 0x40) },
    { RTM_RETIRED_ABORTED_EVENTS,                                       PMC(0xc9, 0x80) },
    { FP_ASSIST_ANY,                                                    PMC_CMASK(0xca, 0x1e, 1) },
    { HW_INTERRUPTS_RECEIVED,                                           PMC(0xcb, 0x01) },
    { MEM_INST_RETIRED_STLB_MISS_LOADS,                                 PMC(0xd0, 0x11) },
    { MEM_INST_RETIRED_STLB_MISS_STORES,                                PMC(0xd0, 0x12) },
    { MEM_INST_RETIRED_LOCK_LOADS,                                      PMC(0xd0, 0x21) },
    { MEM_INST_RETIRED_SPLIT_LOADS,                                     PMC(0xd0, 0x41) },
    { MEM_INST_RETIRED_SPLIT_STORES,                                    PMC(0xd0, 0x42) },
    { MEM_INST_RETIRED_ALL_LOADS,                                       PMC(0xd0, 0x81) },
    { MEM_INST_RETIRED_ALL_STORES,                                      PMC(0xd0, 0x82) },
    { MEM_LOAD_RETIRED_L1_HIT,                                          PMC(0xd1, 0x01) },
    { MEM_LOAD_RETIRED_L2_HIT,                                          PMC(0xd1, 0x02) },
    { MEM_LOAD_RETIRED_L3_HIT,                                          PMC(0xd1, 0x04) },
    { MEM_LOAD_RETIRED_L1_MISS,                                         PMC(0xd1, 0x08) },
    { MEM_LOAD_RETIRED_L2_MISS,                                         PMC(0xd1, 0x10) },
    { MEM_LOAD_RETIRED_L3_MISS,                                         PMC(0xd1, 0x20) },
    { MEM_LOAD_RETIRED_FB_HIT,                                          PMC(0xd1, 0x40) },
    { MEM_LOAD_L3_HIT_RETIRED_X_SNP_MISS,                               PMC(0xd2, 0x01) },
    { MEM_LOAD_L3_HIT_RETIRED_X_SNP_HIT,                                PMC(0xd2, 0x02) },
    { MEM_LOAD_L3_HIT_RETIRED_X_SNP_HITM,                               PMC(0xd2, 0x04) },
    { MEM_LOAD_L3_HIT_RETIRED_X_SNP_NONE,                               PMC(0xd2, 0x08) },
    { MEM_LOAD_L3_MISS_RETIRED_LOCAL_DRAM,                              PMC(0xd3, 0x01) },
    { MEM_LOAD_L3_MISS_RETIRED_REMOTE_DRAM,                             PMC(0xd3, 0x02) },
    { MEM_LOAD_L3_MISS_RETIRED_REMOTE_HITM,                             PMC(0xd3, 0x04) },
    { MEM_LOAD_L3_MISS_RETIRED_REMOTE_FWD,                              PMC(0xd3, 0x08) },
    { MEM_LOAD_MISC_RETIRED_UC,                                         PMC(0xd4, 0x04) },
    { BACLEARS_ANY,                                                     PMC(0xe6, 0x01) },
    { L2_TRANS_L2_WB,                                                   PMC(0xf0, 0x40) },
    { L2_LINES_IN_ALL,                                                  PMC(0xf1, 0x1f) },
    { L2_LINES_OUT_SILENT,                                              PMC(0xf2, 0x01) },
    { L2_LINES_OUT_NON_SILENT,                                          PMC(0xf2, 0x02) },
    { L2_LINES_OUT_USELESS_PREF,                                        PMC(0xf2, 0x04) },
    { L2_LINES_OUT_USELESS_HWPF,                                        PMC(0xf2, 0x04) },
    { SQ_MISC_SPLIT_LOCK,                                               PMC(0xf4, 0x10) },
    { IDI_MISC_WB_UPGRADE,                                              PMC(0xfe, 0x02) },
    { IDI_MISC_WB_DOWNGRADE,                                            PMC(0xfe, 0x04) },
    { 0 }
};

/* Event descriptions for 6th gen, 7th, and 8th gen gen Intel Core processors */
static struct bperf_event_tuple EVENTS_6TH_7TH_8TH_GEN_INTEL_CORE[] = {
    { LD_BLOCKS_STORE_FORWARD,                                          PMC(0x03, 0x02) },
    { LD_BLOCKS_NO_SR,                                                  PMC(0x03, 0x08) },
    { LD_BLOCKS_PARIAL_ADDRESS_ALIAS,                                   PMC(0x07, 0x01) },
    { DTLB_LOAD_MISSES_MISS_CAUSES_A_WALK,                              PMC(0x08, 0x01) },
    { DTLB_LOAD_MISSES_WALK_COMPLETED,                                  PMC(0x08, 0x0e) },
    { DTLB_LOAD_MISSES_WALK_PENDING,                                    PMC(0x08, 0x10) },
    { DTLB_LOAD_MISSES_WALK_ACTIVE,                                     PMC_CMASK(0x08, 0x10, 1) },
    { DTLB_LOAD_MISSES_STLB_HIT,                                        PMC(0x08, 0x20) },
    { INT_MISC_RECOVERY_CYCLES,                                         PMC(0x0d, 0x01) },
    { INT_MISC_CLEAR_RESTEER_CYCLES,                                    PMC(0x0d, 0x80) },
    { UOPS_ISSUED_ANY,                                                  PMC(0x0e, 0x01) },
    { UOPS_ISSUES_STALL_CYCLES,                                         PMC_CMASK_INV(0x0e, 0x01, 1) },
    { UOPS_ISSUED_VECTOR_WIDTH_MISMATCH,                                PMC(0x0e, 0x02) },
    { UOPS_ISSUED_SLOW_LEA,                                             PMC(0x0e, 0x20) },
    { ARITH_FPU_DIVIDER_ACTIVE,                                         PMC(0x14, 0x01) },
    { L2_RQSTS_DEMAND_DATA_RD_MISS,                                     PMC(0x24, 0x21) },
    { L2_RQSTS_RFO_MISS,                                                PMC(0x24, 0x22) },
    { L2_RQSTS_CODE_RD_MISS,                                            PMC(0x24, 0x24) },
    { L2_RQSTS_ALL_DEMAND_MISS,                                         PMC(0x24, 0x27) },
    { L2_RQSTS_PF_MISS,                                                 PMC(0x24, 0x38) },
    { L2_RQSTS_MISS,                                                    PMC(0x24, 0x3f) },
    { L2_RQSTS_DEMAND_DATA_RD_HIT,                                      PMC(0x24, 0x41) },
    { L2_RQSTS_RFO_HIT,                                                 PMC(0x24, 0x42) },
    { L2_RQSTS_CODE_RD_HIT,                                             PMC(0x24, 0x44) },
    { L2_RQSTS_PF_HIT,                                                  PMC(0x24, 0xd8) },
    { L2_RQSTS_ALL_DEMAND_DATA_RD,                                      PMC(0x24, 0xe1) },
    { L2_RQSTS_ALL_RFO,                                                 PMC(0x24, 0xe2) },
    { L2_RQSTS_ALL_CODE_RD,                                             PMC(0x24, 0xe4) },
    { L2_RQSTS_ALL_DEMAND_REFERENCES,                                   PMC(0x24, 0xe7) },
    { L2_RQSTS_ALL_PF,                                                  PMC(0x24, 0xf8) },
    { L2_RQSTS_REFERENCES,                                              PMC(0x24, 0xff) },
    { LONGEST_LAT_CACHE_MISS,                                           PMC(0x2e, 0x41) },
    { LONGEST_LAT_CACHE_REFERENCE,                                      PMC(0x2e, 0x4f) },
    { CPU_CLK_UNHALTED_THREAD,                                          PMC(0x3c, 0x00) },
    { CPU_CLK_UNHALTED_REF_TSC,                                         PMC(0x3c, 0x01) },
    { CPU_CLK_UNHALTED_ONE_THREAD_ACTIVE,                               PMC(0x3c, 0x02) },
    { L1D_PEND_MISS_PENDING,                                            PMC(0x48, 0x01) },
    { L1D_PIND_MISS_PENDING_CYCLES,                                     PMC_CMASK(0x48, 0x01, 1) },
    { L1D_PEND_MISS_FB_FULL,                                            PMC(0x48, 0x02) },
    { DTLB_STORE_MISSES_MISS_CAUSES_A_WALK,                             PMC(0x49, 0x01) },
    { DTLB_STORE_MISSES_WALK_COMPLETED,                                 PMC(0x49, 0x0e) },
    { DTLB_STORE_MISSES_WALK_PENDING,                                   PMC(0x49, 0x10) },
    { DTLB_STORE_MISSES_WALK_ACTIVE,                                    PMC_CMASK(0x49, 0x10, 1) },
    { DTLB_STORE_MISSES_STLB_HIT,                                       PMC(0x49, 0x20) },
    { LOAD_HIT_PRE_SW_PF,                                               PMC(0x4c, 0x01) },
    { EPT_WALK_PENDING,                                                 PMC(0x4f, 0x10) },
    { L1D_REPLACEMENT,                                                  PMC(0x51, 0x01) },
    { RS_EVENTS_EMPTY_CYCLES,                                           PMC(0x5e, 0x01) },
    { RS_EVENTS_EMPTY_END,                                              PMC_CMASK_INV_EDG(0x5e, 0x01, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_DEMAND_DATA_RD,                      PMC(0x60, 0x01) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_DATA_RD,          PMC_CMASK(0x60, 0x01, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_DEMAND_DATA_RD_GE_6,                 PMC_CMASK(0x60, 0x01, 6) },
    { OFFCORE_REQUESTS_OUTSTANDING_DEMAND_CODE_RD,                      PMC(0x60, 0x02) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_CODE_RD,          PMC_CMASK(0x60, 0x02, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_DEMAND_RFO,                          PMC(0x60, 0x04) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DEMAND_RFO,              PMC_CMASK(0x60, 0x04, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_ALL_DATA_RD,                         PMC(0x60, 0x08) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_DATA_RD,                 PMC_CMASK(0x60, 0x08, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_L3_MISS_DEMAND_DATA_RD,              PMC(0x60, 0x10) },
    { OFFCORE_REQUESTS_OUTSTANDING_CYCLES_WITH_L3_MISS_DEMAND_DATA_RD,  PMC_CMASK(0x60, 0x10, 1) },
    { OFFCORE_REQUESTS_OUTSTANDING_L3_MISS_DEMAND_DATA_RD_GE_6,         PMC_CMASK(0x60, 0x10, 6) },
    { LOCK_CYCLES_CACHE_LOCK_DURATION,                                  PMC(0x63, 0x02) },
    { IDQ_MITE_UOPS,                                                    PMC(0x79, 0x04) },
    { IDQ_MITE_CYCLES,                                                  PMC_CMASK(0x79, 0x04, 1) },
    { IDQ_DSB_UOPS,                                                     PMC(0x79, 0x08) },
    { IDQ_DSB_CYCLES,                                                   PMC_CMASK(0x79, 0x08, 1) },
    { IDQ_MS_DSB_UOPS,                                                  PMC(0x79, 0x10) },
    { IDQ_ALL_DSB_CYCLES_ANY_UOPS,                                      PMC_CMASK(0x79, 0x18, 1) },
    { IDQ_ALL_DSB_CYCLES_4_UOPS,                                        PMC_CMASK(0x79, 0x18, 4) },
    { IDQ_MS_MITE_UOPS,                                                 PMC(0x79, 0x20) },
    { IDQ_ALL_MITE_CYCLES_ANY_UOPS,                                     PMC_CMASK(0x79, 0x24, 1) },
    { IDQ_ALL_MITE_CYCLES_4_UOPS,                                       PMC_CMASK(0x79, 0x24, 4) },
    { IDQ_MS_UOPS,                                                      PMC(0x79, 0x30) },
    { IDQ_MS_SWITCHES,                                                  PMC_EDG(0x79, 0x30) },
    { IDQ_MS_CYCLES,                                                    PMC_CMASK(0x79, 0x30, 1) },
    { ICACHE_16B_IFDATA_STALL,                                          PMC(0x80, 0x04) },
    { ICACHE_64B_IFDATA_STALL,                                          PMC(0x80, 0x04) },
    { ICACHE_64B_IFTAG_HIT,                                             PMC(0x83, 0x01) },
    { ICACHE_64B_IFTAG_MISS,                                            PMC(0x83, 0x02) },
    { ITLB_MISSES_MISS_CAUSES_A_WALK,                                   PMC(0x85, 0x01) },
    { ITLB_MISSES_WALK_COMPLETED,                                       PMC(0x85, 0x0e) },
    { ITLB_MISSES_WALK_PENDING,                                         PMC(0x85, 0x10) },
    { ITLB_MISSES_STLB_HIT,                                             PMC(0x85, 0x20) },
    { ILD_STALL_LCP,                                                    PMC(0x87, 0x01) },
    { IDQ_UOPS_NOT_DELIVERED_CORE,                                      PMC(0x9c, 0x01) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_0_UOP_DELIV_CORE,                   PMC_CMASK(0x9c, 0x01, 4) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_LE_1_UOP_DELIV_CORE,                PMC_CMASK(0x9c, 0x01, 3) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_LE_2_UOP_DELIV_CORE,                PMC_CMASK(0x9c, 0x01, 2) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_LE_3_UOP_DELIV_CORE,                PMC_CMASK(0x9c, 0x01, 1) },
    { IDQ_UOPS_NOT_DELIVERED_CYCLES_FE_WAS_OK,                          PMC_CMASK_INV(0x9c, 0x01, 1) },
    { UOPS_DISPATCHED_PORT_PORT_0,                                      PMC(0xa1, 0x01) },
    { UOPS_DISPATCHED_PORT_PORT_1,                                      PMC(0xa1, 0x02) },
    { UOPS_DISPATCHED_PORT_PORT_2,                                      PMC(0xa1, 0x04) },
    { UOPS_DISPATCHED_PORT_PORT_3,                                      PMC(0xa1, 0x08) },
    { UOPS_DISPATCHED_PORT_PORT_4,                                      PMC(0xa1, 0x10) },
    { UOPS_DISPATCHED_PORT_PORT_5,                                      PMC(0xa1, 0x20) },
    { UOPS_DISPATCHED_PORT_PORT_6,                                      PMC(0xa1, 0x40) },
    { UOPS_DISPATCHED_PORT_PORT_7,                                      PMC(0xa1, 0x80) },
    { RESOURCE_STALLS_ANY,                                              PMC(0xa2, 0x01) },
    { RESOURCE_STALLS_SB,                                               PMC(0xa2, 0x08) },
    { CYCLE_ACTIVITY_CYCLES_L2_MISS,                                    PMC(0xa3, 0x01) },
    { CYCLE_ACTIVITY_CYCLES_L3_MISS,                                    PMC(0xa3, 0x02) },
    { CYCLE_ACTIVITY_STALLS_TOTAL,                                      PMC(0xa3, 0x04) },
    { CYCLE_ACTIVITY_STALLS_L2_MISS,                                    PMC(0xa3, 0x05) },
    { CYCLE_ACTIVITY_STALLS_L3_MISS,                                    PMC(0xa3, 0x06) },
    { CYCLE_ACTIVITY_CYCLES_L1D_MISS,                                   PMC(0xa3, 0x08) },
    { CYCLE_ACTIVITY_STALLS_L1D_MISS,                                   PMC(0xa3, 0x0c) },
    { CYCLE_ACTIVITY_CYCLES_MEM_ANY,                                    PMC(0xa3, 0x10) },
    { CYCLE_ACTIVITY_STALLS_MEM_ANY,                                    PMC(0xa3, 0x14) },
    { EXE_ACTIVITY_BOUND_0_PORTS,                                       PMC(0xa6, 0x01) },
    { EXE_ACTIVITY_1_PORTS_UTIL,                                        PMC(0xa6, 0x02) },
    { EXE_ACTIVITY_2_PORTS_UTIL,                                        PMC(0xa6, 0x04) },
    { EXE_ACTIVITY_3_PORTS_UTIL,                                        PMC(0xa6, 0x08) },
    { EXE_ACTIVITY_BOUND_ON_STORES,                                     PMC(0xa6, 0x40) },
    { LSD_UOPS,                                                         PMC(0xa8, 0x01) },
    { LSD_CYCLES_ACTIVE,                                                PMC_CMASK(0xa8, 0x01, 1) },
    { LSD_CYCLES_4_UOPS,                                                PMC_CMASK(0xa8, 0x01, 4) },
    { DSB2MITE_SWITCHES_PENALTY_CYCLES,                                 PMC(0xab, 0x02) },
    { ITLB_ITLB_FLUSH,                                                  PMC(0xae, 0x01) },
    { OFFCORE_REQUESTS_DEMAND_DATA_RD,                                  PMC(0xb0, 0x01) },
    { OFFCORE_REQUESTS_DEMAND_CODE_RD,                                  PMC(0xb0, 0x02) },
    { OFFCORE_REQUESTS_DEMAND_RFO,                                      PMC(0xb0, 0x04) },
    { OFFCORE_REQUESTS_ALL_DATA_RD,                                     PMC(0xb0, 0x08) },
    { OFFCORE_REQUESTS_L3_MISS_DEMAND_DATA_RD,                          PMC(0xb0, 0x10) },
    { OFFCORE_REQUESTS_ALL_REQUESTS,                                    PMC(0xb0, 0x80) },
    { UOPS_EXECUTED_THREAD,                                             PMC(0xb1, 0x01) },
    { UOPS_EXECUTED_STALL_CYCLES,                                       PMC_CMASK_INV(0xb1, 0x01, 1) },
    { UOPS_EXECUTED_CYCLES_GE_1_UOP_EXEC,                               PMC_CMASK(0xb1, 0x01, 1) },
    { UOPS_EXECUTED_CYCLES_GE_2_UOP_EXEC,                               PMC_CMASK(0xb1, 0x01, 2) },
    { UOPS_EXECUTED_CYCLES_GE_3_UOP_EXEC,                               PMC_CMASK(0xb1, 0x01, 3) },
    { UOPS_EXECUTED_CYCLES_GE_4_UOP_EXEC,                               PMC_CMASK(0xb1, 0x01, 4) },
    { UOPS_EXECUTED_CORE,                                               PMC(0xb1, 0x02) },
    { UOPS_EXECUTED_CORE_CYCLES_GE_1,                                   PMC_CMASK(0xb1, 0x02, 1) },
    { UOPS_EXECUTED_CORE_CYCLES_GE_2,                                   PMC_CMASK(0xb1, 0x02, 2) },
    { UOPS_EXECUTED_CORE_CYCLES_GE_3,                                   PMC_CMASK(0xb1, 0x02, 3) },
    { UOPS_EXECUTED_CORE_CYCLES_GE_4,                                   PMC_CMASK(0xb1, 0x02, 4) },
    { UOPS_EXECUTED_CORE_CYCLES_NONE,                                   PMC_CMASK_INV(0xb1, 0x02, 1) },
    { UOPS_EXECUTED_X87,                                                PMC(0xb1, 0x10) },
    { OFF_CORE_REQUEST_BUFFER_SQ_FULL,                                  PMC(0xb2, 0x01) },
    { TLB_FLUSH_DTLB_THREAD,                                            PMC(0xbd, 0x01) },
    { TLB_FLUSH_STLB_ANY,                                               PMC(0xbd, 0x20) },
    { INST_RETIRED_ANY,                                                 PMC(0xc0, 0x00) },
    { OTHER_ASSISTS_ANY,                                                PMC(0xc1, 0x3f) },
    { UOPS_RETIRED_STALL_CYCLES,                                        PMC_CMASK_INV(0xc2, 0x01, 1) },
    { UOPS_RETIRED_TOTAL_CYCLES,                                        PMC_CMASK_INV(0xc2, 0x01, 10) },
    { UOPS_RETIRED_RETIRE_SLOTS,                                        PMC(0xc2, 0x02) },
    { MACHINE_CLEARS_COUNT,                                             PMC(0xc3, 0x01) },
    { MACHINE_CLEARS_MEMORY_ORDERING,                                   PMC(0xc3, 0x02) },
    { MACHINE_CLEARS_SMC,                                               PMC(0xc3, 0x04) },
    { BR_INST_RETIRED_ALL_BRANCHES,                                     PMC(0xc4, 0x00) },
    { BR_INST_RETIRED_CONDITIONAL,                                      PMC(0xc4, 0x01) },
    { BR_INST_RETIRED_NEAR_CALL,                                        PMC(0xc4, 0x02) },
    { BR_INST_RETIRED_NEAR_RETURN,                                      PMC(0xc4, 0x08) },
    { BR_INST_RETIRED_NOT_TAKEN,                                        PMC(0xc4, 0x10) },
    { BR_INST_RETIRED_NEAR_TAKEN,                                       PMC(0xc4, 0x20) },
    { BR_INST_RETIRED_FAR_BRANCH,                                       PMC(0xc4, 0x40) },
    { BR_MISP_RETIRED_ALL_BRANCHES,                                     PMC(0xc5, 0x00) },
    { BR_MISP_RETIRED_CONDITIONAL,                                      PMC(0xc5, 0x01) },
    { BR_MISP_RETIRED_NEAR_TAKEN,                                       PMC(0xc5, 0x20) },
    { FP_ARITH_INST_RETIRED_SCALAR_DOUBLE,                              PMC(0xc7, 0x01) },
    { FP_ARITH_INST_RETIRED_SCALAR_SINGLE,                              PMC(0xc7, 0x02) },
    { FP_ARITH_INST_RETIRED_128B_PACKED_DOUBLE,                         PMC(0xc7, 0x04) },
    { FP_ARITH_INST_RETIRED_128B_PACKED_SINGLE,                         PMC(0xc7, 0x08) },
    { FP_ARITH_INST_RETIRED_256B_PACKED_DOUBLE,                         PMC(0xc7, 0x10) },
    { FP_ARITH_INST_RETIRED_256B_PACKED_SINGLE,                         PMC(0xc7, 0x20) },
    { FP_ASSIST_ANY,                                                    PMC_CMASK(0xca, 0x1e, 1) },
    { HW_INTERRUPTS_RECEIVED,                                           PMC(0xcb, 0x01) },
    { MEM_INST_RETIRED_STLB_MISS_LOADS,                                 PMC(0xd0, 0x11) },
    { MEM_INST_RETIRED_STLB_MISS_STORES,                                PMC(0xd0, 0x12) },
    { MEM_INST_RETIRED_LOCK_LOADS,                                      PMC(0xd0, 0x21) },
    { MEM_INST_RETIRED_SPLIT_LOADS,                                     PMC(0xd0, 0x41) },
    { MEM_INST_RETIRED_SPLIT_STORES,                                    PMC(0xd0, 0x42) },
    { MEM_INST_RETIRED_ALL_LOADS,                                       PMC(0xd0, 0x81) },
    { MEM_INST_RETIRED_ALL_STORES,                                      PMC(0xd0, 0x82) },
    { MEM_LOAD_RETIRED_L1_HIT,                                          PMC(0xd1, 0x01) },
    { MEM_LOAD_RETIRED_L2_HIT,                                          PMC(0xd1, 0x02) },
    { MEM_LOAD_RETIRED_L3_HIT,                                          PMC(0xd1, 0x04) },
    { MEM_LOAD_RETIRED_L1_MISS,                                         PMC(0xd1, 0x08) },
    { MEM_LOAD_RETIRED_L2_MISS,                                         PMC(0xd1, 0x10) },
    { MEM_LOAD_RETIRED_L3_MISS,                                         PMC(0xd1, 0x20) },
    { MEM_LOAD_RETIRED_FB_HIT,                                          PMC(0xd1, 0x40) },
    { MEM_LOAD_L3_HIT_RETIRED_X_SNP_MISS,                               PMC(0xd2, 0x01) },
    { MEM_LOAD_L3_HIT_RETIRED_X_SNP_HIT,                                PMC(0xd2, 0x02) },
    { MEM_LOAD_L3_HIT_RETIRED_X_SNP_HITM,                               PMC(0xd2, 0x04) },
    { MEM_LOAD_L3_HIT_RETIRED_X_SNP_NONE,                               PMC(0xd2, 0x08) },
    { BACLEARS_ANY,                                                     PMC(0xe6, 0x01) },
    { L2_TRANS_L2_WB,                                                   PMC(0xf0, 0x40) },
    { L2_LINES_IN_ALL,                                                  PMC(0xf1, 0x07) },
    { 0 }
};

#undef PMC
#undef PMC_CMASK
#undef PMC_EDG
#undef PMC_CMASK_INV
#undef PMC_CMASK_EDG
#undef PMC_CMASK_INV_EDG

/**
 * @brief Static knowledgebase of architecture-specific event numbers and umasks
 */
static struct bperf_arch_events EVENTS[] = {
    { 0x06, 0x55, EVENTS_06_55 },
    { 0x06, 0x4e, EVENTS_6TH_7TH_8TH_GEN_INTEL_CORE },
    { 0x06, 0x5e, EVENTS_6TH_7TH_8TH_GEN_INTEL_CORE },
    { 0x06, 0x8e, EVENTS_6TH_7TH_8TH_GEN_INTEL_CORE },
    { 0x06, 0x9e, EVENTS_6TH_7TH_8TH_GEN_INTEL_CORE },
};

/**
 * @brief Get architecture-specific description of event
 */
const struct bperf_event* bperf_get_arch_event(enum bperf_event_id id, uint8_t family, uint8_t model)
{
    size_t evi, archi, n_archs = sizeof(EVENTS) / sizeof(EVENTS[0]);
    for (archi = 0; archi < n_archs; archi++) {
        if (EVENTS[archi].family != family || EVENTS[archi].model != model) {
            continue;
        }
        for (evi = 0; EVENTS[archi].events[evi].id != 0; evi++) {
            return &EVENTS[archi].events[evi].ev;
        }
    }
    return NULL;
}
