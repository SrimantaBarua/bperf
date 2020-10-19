/**
 * @file    hardware.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    17 October 2020
 * @version 0.1
 * @brief   Split off logic for r/w MSRs and CPUID. Is directly included, not compiled separately
 */

/* MSR numbers */
#define MSR_PMC(x)                   (0xc1U + (x))
#define MSR_PERFEVTSEL(x)            (0x186U + (x))
#define MSR_FIXED_CTR(x)             (0x309U + (x))
#define MSR_PERF_CAPABILITIES        0x345
#define MSR_FIXED_CTR_CTRL           0x38d /* If version > 1 */
#define MSR_PERF_GLOBAL_STATUS       0x38e
#define MSR_PERF_GLOBAL_CTRL         0x38f
#define MSR_PERF_GLOBAL_OVF_CTRL     0x390 /* If version > 0 && version <= 3 */
#define MSR_PERF_GLOBAL_STATUS_RESET 0x390 /* If version > 3 */
#define MSR_PERF_GLOBAL_STATUS_SET   0x391 /* If version > 3 */
#define MSR_PERF_GLOBAL_INUSE        0x392 /* If version > 3 */

/* Architectural performance monitoring event select and umask */
#define PERFEVTSEL_CORE_CYCLES 0x003cUL
#define PERFEVTSEL_INST_RET    0x00c0UL
#define PERFEVTSEL_REF_CYCLES  0x013cUL
#define PERFEVTSEL_LLC_REF     0x4f2eUL
#define PERFEVTSEL_LLC_MISS    0x412eUL
#define PERFEVTSEL_BRANCH_RET  0x00c4UL
#define PERFEVTSEL_BRANCH_MISS 0x00c5UL
/* Architectural performance monitoring flags */
#define PERFEVTSEL_RESERVED     0xffffffff00280000UL
#define PERFEVTSEL_FLAG_USR     0x10000UL
#define PERFEVTSEL_FLAG_OS      0x20000UL
#define PERFEVTSEL_FLAG_ANYTHRD 0x200000UL
#define PERFEVTSEL_FLAG_ENABLE  0x400000UL
#define PERFEVTSEL_FLAGS_SANE   (PERFEVTSEL_FLAG_USR | PERFEVTSEL_FLAG_OS | PERFEVTSEL_FLAG_ENABLE)

/* Fixed counter ctrl */
#define FIXED_CTRL_RESERVED 0xfffffffffffff000UL
#define FIXED_CTRL_EN(x)    (0x003UL << ((x) * 4))
#define FIXED_CTRL_ANY(x)   (0x004UL << ((x) * 4))

/* Global counter ctrl */
#define GLOBAL_CTRL_RESERVED 0xfffffff8fffffff0
#define GLOBAL_CTRL_PMC(x)   (1UL << (x))
#define GLOBAL_CTRL_FIXED(x) (1UL << (32 + (x)))

/* Global counter overflow status */
#define GLOBAL_STATUS_PMC(x)   (1UL << (x))
#define GLOBAL_STATUS_FIXED(x) (1UL << (32 + (x)))
#define GLOBAL_STATUS_UNCORE   (1UL << 61) /* If version >= 3 */
#define GLOBAL_STATUS_DSBUF    (1UL << 62)
#define GLOBAL_STATUS_CONDCHG  (1UL << 63)

/* Global counter overflow ctrl */
#define GLOBAL_OVFCTRL_CLR_PMC(x)   (1UL << (x))
#define GLOBAL_OVFCTRL_CLR_FIXED(x) (1UL << (32 + (x)))
#define GLOBAL_OVFCTRL_CLR_UNCORE   (1UL << 61) /* If version >= 3 */
#define GLOBAL_OVFCTRL_CLR_DSBUF    (1UL << 62)
#define GLOBAL_OVFCTRL_CLR_CONDCHG  (1UL << 63)


/* Check flags in perfevtselx MSR data */
#define PERFEVTSEL_ENABLED(x) (((x) & PERFEVTSEL_FLAG_ENABLE) != 0)

/**
 * @brief Read 64-bit data from an MSR
 */
static uint64_t bperf_rdmsr(uint32_t msr)
{
	uint32_t eax, edx;
	__asm__("rdmsr\n" : "=a"(eax), "=d"(edx) : "c"(msr) : );
	return ((uint64_t) edx << 32) | eax;
}

/**
 * @brief Write 64-bit data to MSR
 */
static void bperf_wrmsr(uint32_t msr, uint64_t val)
{
	uint32_t eax, edx;
	edx = (val >> 32) & 0xffffffff;
	eax = val & 0xffffffff;
	__asm__("wrmsr\n" : : "a"(eax), "d"(edx), "c"(msr) : "memory");
}

/**
 * @brief Get information from CPUID
 */
static void bperf_cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	__asm__("cpuid\n" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "a"(*eax), "c"(*ecx) : );
}
