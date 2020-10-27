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
 * @brief Get integer event ID for event name. 0 on failure
 */
enum bperf_event_id bperf_get_event_id(const char *name) {
#define DEF_EVENT(x, y) do { \
    if (!strcmp(name, #x "." #y)) { \
        return x ## _ ## y; \
    } \
} while (0)

    DEF_EVENT(INST_RETIRED, ANY);
    DEF_EVENT(CPU_CLK_UNHALTED, THREAD);
    DEF_EVENT(CPU_CLK_UNHALTED, REF_TSC);
    DEF_EVENT(LD_BLOCKS, STORE_FORWARD);
    DEF_EVENT(LD_BLOCKS, NO_SR);
    DEF_EVENT(LD_BLOCKS_PARIAL, ADDRESS_ALIAS);
    DEF_EVENT(DTLB_LOAD_MISSES, MISS_CAUSES_A_WALK);
    DEF_EVENT(DTLB_LOAD_MISSES, WALK_COMPLETED_4K);
    DEF_EVENT(DTLB_LOAD_MISSES, WALK_COMPLETED_2M_4M);
    DEF_EVENT(DTLB_LOAD_MISSES, WALK_COMPLETED_1G);
    DEF_EVENT(DTLB_LOAD_MISSES, WALK_COMPLETED);
    DEF_EVENT(DTLB_LOAD_MISSES, WALK_PENDING);
    DEF_EVENT(DTLB_LOAD_MISSES, WALK_ACTIVE);
    DEF_EVENT(DTLB_LOAD_MISSES, STLB_HIT);
    DEF_EVENT(INT_MISC, RECOVERY_CYCLES);
    DEF_EVENT(INT_MISC, CLEAR_RESTEER_CYCLES);
    DEF_EVENT(UOPS_ISSUED, ANY);
    DEF_EVENT(UOPS_ISSUES, STALL_CYCLES);
    DEF_EVENT(UOPS_ISSUED, VECTOR_WIDTH_MISMATCH);
    DEF_EVENT(UOPS_ISSUED, SLOW_LEA);
    DEF_EVENT(ARITH, DIVIDER_ACTIVE);
    DEF_EVENT(L2_RQSTS, DEMAND_DATA_RD_MISS);
    DEF_EVENT(L2_RQSTS, RFO_MISS);
    DEF_EVENT(L2_RQSTS, CODE_RD_MISS);
    DEF_EVENT(L2_RQSTS, ALL_DEMAND_MISS);
    DEF_EVENT(L2_RQSTS, PF_MISS);
    DEF_EVENT(L2_RQSTS, MISS);
    DEF_EVENT(L2_RQSTS, DEMAND_DATA_RD_HIT);
    DEF_EVENT(L2_RQSTS, RFO_HIT);
    DEF_EVENT(L2_RQSTS, CODE_RD_HIT);
    DEF_EVENT(L2_RQSTS, PF_HIT);
    DEF_EVENT(L2_RQSTS, ALL_DEMAND_DATA_RD);
    DEF_EVENT(L2_RQSTS, ALL_RFO);
    DEF_EVENT(L2_RQSTS, ALL_CODE_RD);
    DEF_EVENT(L2_RQSTS, ALL_DEMAND_REFERENCES);
    DEF_EVENT(L2_RQSTS, ALL_PF);
    DEF_EVENT(L2_RQSTS, REFERENCES);
    DEF_EVENT(CORE_POWER, LVL0_TURBO_LICENSE);
    DEF_EVENT(CORE_POWER, LVL1_TURBO_LICENSE);
    DEF_EVENT(CORE_POWER, LVL2_TURBO_LICENSE);
    DEF_EVENT(CORE_POWER, THROTTLE);
    DEF_EVENT(LONGEST_LAT_CACHE, MISS);
    DEF_EVENT(LONGEST_LAT_CACHE, REFERENCE);
    DEF_EVENT(CPU_CLK_UNHALTED, THREAD_P);
    DEF_EVENT(CPU_CLK_UNHALTED, RING0_TRANS);
    DEF_EVENT(CPU_CLK_UNHALTED, REF_XCLK);
    DEF_EVENT(CPU_CLK_UNHALTED, ONE_THREAD_ACTIVE);
    DEF_EVENT(L1D_PEND_MISS, PENDING);
    DEF_EVENT(L1D_PIND_MISS, PENDING_CYCLES);
    DEF_EVENT(L1D_PEND_MISS, FB_FULL);
    DEF_EVENT(DTLB_STORE_MISSES, MISS_CAUSES_A_WALK);
    DEF_EVENT(DTLB_STORE_MISSES, WALK_COMPLETED_4K);
    DEF_EVENT(DTLB_STORE_MISSES, WALK_COMPLETED_2M_4M);
    DEF_EVENT(DTLB_STORE_MISSES, WALK_COMPLETED_1G);
    DEF_EVENT(DTLB_STORE_MISSES, WALK_COMPLETED);
    DEF_EVENT(DTLB_STORE_MISSES, WALK_PENDING);
    DEF_EVENT(DTLB_STORE_MISSES, WALK_ACTIVE);
    DEF_EVENT(DTLB_STORE_MISSES, STLB_HIT);
    DEF_EVENT(LOAD_HIT_PRE, SW_PF);
    DEF_EVENT(EPT, WALK_PENDING);
    DEF_EVENT(L1D, REPLACEMENT);
    DEF_EVENT(TX_MEM, ABORT_CONFLICT);
    DEF_EVENT(TX_MEM, ABORT_CAPACITY);
    DEF_EVENT(TX_MEM, ABORT_HLE_STORE_TO_ELIDED_LOCK);
    DEF_EVENT(TX_MEM, ABORT_HLE_ELISION_BUFFER_NOT_EMPTY);
    DEF_EVENT(TX_MEM, ABORT_HLE_ELISION_BUFFER_MISMATCH);
    DEF_EVENT(TX_MEM, ABORT_HLE_ELISION_BUFFER_UNSUPPORTED_ALIGNMENT);
    DEF_EVENT(TX_MEM, ABORT_HLE_ELISION_BUFFER_FULL);
    DEF_EVENT(TX_EXEC, MISC1);
    DEF_EVENT(TX_EXEC, MISC2);
    DEF_EVENT(TX_EXEC, MISC3);
    DEF_EVENT(TX_EXEC, MISC4);
    DEF_EVENT(TX_EXEC, MISC5);
    DEF_EVENT(RS_EVENTS, EMPTY_CYCLES);
    DEF_EVENT(RS_EVENTS, EMPTY_END);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, DEMAND_DATA_RD);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_DEMAND_DATA_RD);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, DEMAND_DATA_RD_GE_6);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, DEMAND_CODE_RD);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_DEMAND_CODE_RD);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, DEMAND_RFO);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_DEMAND_RFO);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, ALL_DATA_RD);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_DATA_RD);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, L3_MISS_DEMAND_DATA_RD);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, CYCLES_WITH_L3_MISS_DEMAND_DATA_RD);
    DEF_EVENT(OFFCORE_REQUESTS_OUTSTANDING, L3_MISS_DEMAND_DATA_RD_GE_6);
    DEF_EVENT(IDQ, MITE_UOPS);
    DEF_EVENT(IDQ, MITE_CYCLES);
    DEF_EVENT(IDQ, DSB_UOPS);
    DEF_EVENT(IDQ, DSB_CYCLES);
    DEF_EVENT(IDQ, MS_DSB_CYCLES);
    DEF_EVENT(IDQ, ALL_DSB_CYCLES_4_UOPS);
    DEF_EVENT(IDQ, ALL_DSB_CYCLES_ANY_UOPS);
    DEF_EVENT(IDQ, MS_MITE_UOPS);
    DEF_EVENT(IDQ, ALL_MITE_CYCLES_4_UOPS);
    DEF_EVENT(IDQ, ALL_MITE_CYCLES_ANY_UOPS);
    DEF_EVENT(IDQ, MS_CYCLES);
    DEF_EVENT(IDQ, MS_SWITCHES);
    DEF_EVENT(IDQ, MS_UOPS);
    DEF_EVENT(ICACHE_16B, IFDATA_STALL);
    DEF_EVENT(ICACHE_64B, IFTAG_HIT);
    DEF_EVENT(ICACHE_64B, IFTAG_MISS);
    DEF_EVENT(ICACHE_64B, IFTAG_STALL);
    DEF_EVENT(ITLB_MISSES, MISS_CAUSES_A_WALK);
    DEF_EVENT(ITLB_MISSES, WALK_COMPLETED_4K);
    DEF_EVENT(ITLB_MISSES, WALK_COMPLETED_2M_4M);
    DEF_EVENT(ITLB_MISSES, WALK_COMPLETED_1G);
    DEF_EVENT(ITLB_MISSES, WALK_COMPLETED);
    DEF_EVENT(ITLB_MISSES, WALK_PENDING);
    DEF_EVENT(ITLB_MISSES, WALK_ACTIVE);
    DEF_EVENT(ITLB_MISSES, STLB_HIT);

    return 0;
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
#define FIXED(num)                    { true, { .fixed_num = num } }
#define PMC(ev, um)                   { false, { .pmc = { .ev_num = ev, .umask = um, .cmask = 0,  .inv = false, .edge = false } } }
#define PMC_CMASK(ev, um, cm)         { false, { .pmc = { .ev_num = ev, .umask = um, .cmask = cm, .inv = false, .edge = false } } }
#define PMC_CMASK_INV(ev, um, cm)     { false, { .pmc = { .ev_num = ev, .umask = um, .cmask = cm, .inv = true, .edge = false } } }
#define PMC_CMASK_EDG(ev, um, cm)     { false, { .pmc = { .ev_num = ev, .umask = um, .cmask = cm, .inv = false, .edge = true } } }
#define PMC_CMASK_INV_EDG(ev, um, cm) { false, { .pmc = { .ev_num = ev, .umask = um, .cmask = cm, .inv = true, .edge = true } } }

/* Event definitions for 06_55 */
static struct bperf_event_tuple EVENTS_06_55[] = {
    { INST_RETIRED_ANY,                                                 FIXED(0) },
    { CPU_CLK_UNHALTED_THREAD,                                          FIXED(1) },
    { CPU_CLK_UNHALTED_REF_TSC,                                         FIXED(2) },
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
    { CPU_CLK_UNHALTED_THREAD_P,                                        PMC(0x3c, 0x00) },
    { CPU_CLK_UNHALTED_RING0_TRANS,                                     PMC_CMASK_EDG(0x3c, 0x00, 1) },
    { CPU_CLK_UNHALTED_REF_XCLK,                                        PMC(0x3c, 0x01) },
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
    { IDQ_ALL_DSB_CYCLES_4_UOPS,                                        PMC_CMASK(0x79, 0x18, 4) },
    { IDQ_ALL_DSB_CYCLES_ANY_UOPS,                                      PMC_CMASK(0x79, 0x18, 1) },
    { IDQ_MS_MITE_UOPS,                                                 PMC(0x79, 0x20) },
    { IDQ_ALL_MITE_CYCLES_4_UOPS,                                       PMC_CMASK(0x79, 0x24, 4) },
    { IDQ_ALL_MITE_CYCLES_ANY_UOPS,                                     PMC_CMASK(0x79, 0x24, 1) },
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
    /* TODO: Add more events */
    { 0 }
};

/* Event descriptions for 6th gen, 7th gen, 8th gen Intel Core processors */
static struct bperf_event_tuple EVENTS_6TH_7TH_8TH_GEN_INTEL_CORE[] = {
    { LD_BLOCKS_STORE_FORWARD,             PMC(0x03, 0x02) },
    { LD_BLOCKS_NO_SR,                     PMC(0x03, 0x08) },
    { LD_BLOCKS_PARIAL_ADDRESS_ALIAS,      PMC(0x07, 0x01) },
    { DTLB_LOAD_MISSES_MISS_CAUSES_A_WALK, PMC(0x08, 0x01) },
    { DTLB_LOAD_MISSES_WALK_COMPLETED,     PMC(0x08, 0x0e) },
    { DTLB_LOAD_MISSES_WALK_PENDING,       PMC(0x08, 0x10) },
    { DTLB_LOAD_MISSES_WALK_ACTIVE,        PMC_CMASK(0x08, 0x10, 1) },
    { 0 }
};

#undef FIXED
#undef PMC
#undef PMC_CMASK
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
const struct bperf_event* bperf_get_arch_event(enum bperf_event_id id, uint8_t family, uint8_t model) {
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