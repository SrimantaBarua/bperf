/**
 * @file    bperf.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    27 September 2020
 * @version 0.1
 * @brief   A kernel module for high frequency counter sampling on x86_64 systems
 */

#include <stdarg.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <asm/smp.h>

#include "arch_def_macro.h"

#define BPERF_NAME             "bperf"
#define BPERF_LICENSE          "MIT"
#define BPERF_AUTHOR           "Srimanta Barua <srimanta.barua1@gmail.com>"
#define BPERF_DESC             "Kernel module for high frequency counter sampling on x86_64 systems"
#define BPERF_VERSION          "0.1"
#define BPERF_MIN_ARCH         2
#define BPERF_DEFAULT_INTERVAL 20
#define BPERF_MAX_PMC          4
#define BPERF_MAX_FIXED        3

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

// ======== Events ================

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
 * @brief Get name for fixed counter
 */
static const char* bperf_get_fixed_ctr_name(size_t i) {
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
static enum bperf_event_id bperf_get_event_id(const char *name, size_t len)
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

static const char* bperf_get_event_name(enum bperf_event_id id)
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

// Helper macros for static event definitions
#define PMC(x, y, ev, um)                   { x ## _ ##  y , { .ev_num = ev, .umask = um, .cmask = 0,  .inv = false, .edge = false } }
#define PMC_CMASK(x, y, ev, um, cm)         { x ## _ ##  y , { .ev_num = ev, .umask = um, .cmask = cm, .inv = false, .edge = false } }
#define PMC_EDG(x, y, ev, um)               { x ## _ ##  y , { .ev_num = ev, .umask = um, .cmask = 0, .inv = false, .edge = true } }
#define PMC_CMASK_INV(x, y, ev, um, cm)     { x ## _ ##  y , { .ev_num = ev, .umask = um, .cmask = cm, .inv = true, .edge = false } }
#define PMC_CMASK_EDG(x, y, ev, um, cm)     { x ## _ ##  y , { .ev_num = ev, .umask = um, .cmask = cm, .inv = false, .edge = true } }
#define PMC_CMASK_INV_EDG(x, y, ev, um, cm) { x ## _ ##  y , { .ev_num = ev, .umask = um, .cmask = cm, .inv = true, .edge = true } }

#include "arch_events.c"

#undef PMC
#undef PMC_CMASK
#undef PMC_EDG
#undef PMC_CMASK_INV
#undef PMC_CMASK_EDG
#undef PMC_CMASK_INV_EDG

/**
 * @brief Get architecture-specific description of event
 */
static const struct bperf_event* bperf_get_arch_event(enum bperf_event_id id, uint8_t family, uint8_t model)
{
    size_t evi, archi, n_archs = sizeof(EVENTS) / sizeof(EVENTS[0]);
    for (archi = 0; archi < n_archs; archi++) {
        if (EVENTS[archi].family != family || EVENTS[archi].model != model) {
            continue;
        }
        for (evi = 0; EVENTS[archi].events[evi].id != 0; evi++) {
            if (EVENTS[archi].events[evi].id == id) {
                return &EVENTS[archi].events[evi].ev;
            }
        }
    }
    return NULL;
}

// ======== MSRs, hardware counters ========

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
#define PERFEVTSEL_CMASK(x)     (((uint64_t) (x) & 0xff) << 24)
#define PERFEVTSEL_UMASK(x)     (((uint64_t) (x) & 0xff) << 8)
#define PERFEVTSEL_EVSEL(x)     ((uint64_t) (x) & 0xff)
#define PERFEVTSEL_FLAG_USR     0x010000UL
#define PERFEVTSEL_FLAG_OS      0x020000UL
#define PERFEVTSEL_FLAG_EDGE    0x040000UL
#define PERFEVTSEL_FLAG_PC      0x080000UL
#define PERFEVTSEL_FLAG_INT     0x100000UL
#define PERFEVTSEL_FLAG_ANYTHRD 0x200000UL
#define PERFEVTSEL_FLAG_ENABLE  0x400000UL
#define PERFEVTSEL_FLAG_INV     0x800000UL

static inline uint64_t perfevtsel_from_ev(const struct bperf_event *e) {
    uint64_t ret;
    ret = PERFEVTSEL_CMASK(e->cmask) | PERFEVTSEL_UMASK(e->umask) | PERFEVTSEL_EVSEL(e->ev_num);
    if (e->inv) {
        ret |= PERFEVTSEL_FLAG_INV;
    }
    if (e->edge) {
        ret |= PERFEVTSEL_FLAG_EDGE;
    }
    return ret;
}

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

// ======== Module state ==========

/**
 * @brief Global module state
 */
static struct bperf_state {
    /* Kernel state */
    dev_t          dev;     /* Stores the device number */
    struct class   *class;  /* The device-driver class struct */
    struct device  *device; /* The device-driver device struct */
    struct cdev    cdev;    /* Char device structure */
    struct kobject *kobj;   /* Kernel object for sysfs */
    /* System information */
    uint32_t family; /* Display_Family */
    uint32_t model;  /* Display_Model */
    /* Module information */
    size_t             num_threads;     /* Number of threads we spawned */
    size_t             sample_interval; /* Sample interval in milliseconds */
    struct task_struct **thread_ptr;    /* Pointers to task struct for kernel thread */
    /* Performance monitoring capabilities */
    bool                enabled;       /* Whether performance monitoring is enabled */
    uint32_t            arch_perf_ver; /* Version ID of architectural performance monitoring */
    uint32_t            num_pmc;       /* Number of general purpose performance monitoring counters */
    uint32_t            num_fixed;     /* Number of fixed function performance monitoring counters */
    uint32_t            ctr_width;     /* Bit width of general purpose counters */
    uint32_t            fix_ctr_width; /* Bit width of fixed function counters */
    /* Whether specific events are available */
    bool ev_core_cycle;        /* Core cycle event available */
    bool ev_inst_retired;      /* Instruction retired event available */
    bool ev_ref_cycles;        /* Reference cycles event available */
    bool ev_llc_ref;           /* LLC reference event available */
    bool ev_llc_miss;          /* LLC miss event available */
    bool ev_branch_retired;    /* Branch instruction retired event available */
    bool ev_branch_mispredict; /* Branch mispredict retired event available */
    /* Performance monitoring state */
    enum bperf_event_id pmc_id[BPERF_MAX_PMC]; /* Configured event for each PMC */
} STATE = { 0 };

/**
 * @brief Waitqueue for performance monitoring threads
 */
static DECLARE_WAIT_QUEUE_HEAD(ENABLED_WQ);

// ======== Userspace-visible module state ========

static ssize_t sample_interval_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%lu\n", STATE.sample_interval);
}

static ssize_t sample_interval_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    uint32_t interval;
    int ret;
    if (STATE.enabled) {
        return -EBUSY;
    }
    if ((ret = kstrtou32(buf, 10, &interval))) {
        return ret;
    }
    STATE.sample_interval = interval;
    return count;
}

static ssize_t num_cores_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%lu\n", STATE.num_threads);
}

static ssize_t cpu_family_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", STATE.family);
}

static ssize_t cpu_model_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", STATE.model);
}

static ssize_t num_pmc_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", STATE.num_pmc);
}

static ssize_t num_fixed_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", STATE.num_fixed);
}

static ssize_t arch_perf_ver_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", STATE.arch_perf_ver);
}

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, STATE.enabled ? "enabled\n" : "disabled\n");
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    while (count > 0 && buf[count - 1] == '\n') {
        count--;
    }
    if (!strncmp(buf, "enable", count)) {
        STATE.enabled = true;
        wake_up_interruptible(&ENABLED_WQ);
        return count;
    } else if (!strncmp(buf, "disable", count)) {
        STATE.enabled = false;
        return count;
    } else {
        return -EINVAL;
    }
}

static ssize_t pmc0_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%s\n", bperf_get_event_name(STATE.pmc_id[0]));
}

static ssize_t pmc0_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    enum bperf_event_id id;
    if (STATE.enabled) {
        return -EBUSY;
    }
    while (count > 0 && buf[count - 1] == '\n') {
        count--;
    }
    id = bperf_get_event_id(buf, count);
    if (id == __UNKNOWN_EVENT__) {
        return -EINVAL;
    } else {
        STATE.pmc_id[0] = id;
        return count;
    }
}

static ssize_t pmc1_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%s\n", bperf_get_event_name(STATE.pmc_id[1]));
}

static ssize_t pmc1_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    enum bperf_event_id id;
    if (STATE.enabled) {
        return -EBUSY;
    }
    while (count > 0 && buf[count - 1] == '\n') {
        count--;
    }
    id = bperf_get_event_id(buf, count);
    if (id == __UNKNOWN_EVENT__) {
        return -EINVAL;
    } else {
        STATE.pmc_id[1] = id;
        return count;
    }
}

static ssize_t pmc2_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%s\n", bperf_get_event_name(STATE.pmc_id[2]));
}

static ssize_t pmc2_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    enum bperf_event_id id;
    if (STATE.enabled) {
        return -EBUSY;
    }
    while (count > 0 && buf[count - 1] == '\n') {
        count--;
    }
    id = bperf_get_event_id(buf, count);
    if (id == __UNKNOWN_EVENT__) {
        return -EINVAL;
    } else {
        STATE.pmc_id[2] = id;
        return count;
    }
}

static ssize_t pmc3_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%s\n", bperf_get_event_name(STATE.pmc_id[3]));
}

static ssize_t pmc3_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    enum bperf_event_id id;
    if (STATE.enabled) {
        return -EBUSY;
    }
    while (count > 0 && buf[count - 1] == '\n') {
        count--;
    }
    id = bperf_get_event_id(buf, count);
    if (id == __UNKNOWN_EVENT__) {
        return -EINVAL;
    } else {
        STATE.pmc_id[3] = id;
        return count;
    }
}

static struct kobj_attribute sample_interval_attr = __ATTR_RW(sample_interval);
static struct kobj_attribute num_cores_attr       = __ATTR_RO(num_cores);
static struct kobj_attribute cpu_family_attr      = __ATTR_RO(cpu_family);
static struct kobj_attribute cpu_model_attr       = __ATTR_RO(cpu_model);
static struct kobj_attribute num_pmc_attr         = __ATTR_RO(num_pmc);
static struct kobj_attribute num_fixed_attr       = __ATTR_RO(num_fixed);
static struct kobj_attribute arch_perf_ver_attr   = __ATTR_RO(arch_perf_ver);
static struct kobj_attribute enabled_attr         = __ATTR_RW(enabled);
// TODO: Align with BPERF_MAX_PMC
static struct kobj_attribute pmc_attrs[] = {
    __ATTR_RW(pmc0),
    __ATTR_RW(pmc1),
    __ATTR_RW(pmc2),
    __ATTR_RW(pmc3),
};

// ======== String buffer ========

#define BPERF_SBUFFER_BLK_SZ    2048

/**
 * @brief Linked list node of circular string buffer
 *
 * Total size of a node is BPERF_SBUFFER_BLK_SZ bytes. This size includes this "header" struct.
 * The data starts immediately after it.
 */
struct bperf_sbuffer_node {
    size_t           start; /* Start index of unread data in this node */
    size_t           size;  /* Amount of data stored in this node */
    struct list_head list;  /* Linked list node */
    /* Data follows immediately after this */
};

#define BPERF_SBUFFER_MAX_SZ (BPERF_SBUFFER_BLK_SZ - sizeof(struct bperf_sbuffer_node))

/**
 * @brief Get pointer to dat for node
 */
static char* bperf_sbuffer_node_data(struct bperf_sbuffer_node *node)
{
    return ((char*) node) + sizeof(struct bperf_sbuffer_node);
}

/**
 * @brief Allocate a new empty buffer node
 */
static struct bperf_sbuffer_node* bperf_sbuffer_node_new(void)
{
    struct bperf_sbuffer_node *ret = kmalloc(BPERF_SBUFFER_BLK_SZ, GFP_KERNEL);
    if (!ret || IS_ERR(ret)) {
        printk(KERN_ALERT "bperf: kmalloc failed\n");
        return NULL;
    }
    ret->start = ret->size = 0;
    INIT_LIST_HEAD(&ret->list);
    return ret;
}

/**
 * @brief Free memory for an allocated buffer node
 */
static void bperf_sbuffer_node_free(struct bperf_sbuffer_node *node)
{
    list_del(&node->list);
    kfree(node);
}

/**
 * @brief Circular buffer to write data to
 */
static struct bperf_sbuffer {
    struct list_head  list;  /* Head node to linked list of buffers */
    struct mutex      mutex; /* Mutex for access to the buffer */
    size_t            size;  /* Amount of data currently in buffer */
    wait_queue_head_t waitq; /* Wait queue of readers */
} SBUFFER = { 0 };

/**
 * @brief Initialize buffer
 */
static int bperf_sbuffer_init(struct bperf_sbuffer *sbuffer)
{
    struct bperf_sbuffer_node *first_node;
    INIT_LIST_HEAD(&sbuffer->list);
    if (!(first_node = bperf_sbuffer_node_new())) {
        return -ENOMEM;
    }
    list_add(&first_node->list, &sbuffer->list);
    mutex_init(&sbuffer->mutex);
    init_waitqueue_head(&sbuffer->waitq);
    sbuffer->size = 0;
    return 0;
}

/**
 * @brief Free memory for buffer without reinitializing the mutex etc.
 */
static void bperf_sbuffer_clear(struct bperf_sbuffer *sbuffer) {
    struct list_head *next, *node;
    mutex_lock_interruptible(&sbuffer->mutex);
    sbuffer->size = 0;
    node = sbuffer->list.next;
    while (node != &sbuffer->list) {
        next = node->next;
        bperf_sbuffer_node_free(container_of(node, struct bperf_sbuffer_node, list));
        node = next;
    }
    INIT_LIST_HEAD(&sbuffer->list);
    mutex_unlock(&sbuffer->mutex);
}

/**
 * @brief Free memory for buffer
 */
static void bperf_sbuffer_fini(struct bperf_sbuffer *sbuffer)
{
    struct list_head *next, *node;
    mutex_lock_interruptible(&sbuffer->mutex);
    node = sbuffer->list.next;
    while (node != &sbuffer->list) {
        next = node->next;
        bperf_sbuffer_node_free(container_of(node, struct bperf_sbuffer_node, list));
        node = next;
    }
    mutex_unlock(&sbuffer->mutex);
    mutex_destroy(&sbuffer->mutex);
}

/**
 * @brief Write len bytes of data to the end of the buffer
 */
static ssize_t bperf_sbuffer_write(struct bperf_sbuffer *sbuffer, char *src, size_t len)
{
    struct bperf_sbuffer_node *last_node, *new_node;
    ssize_t space_left, amt_to_write, ret = 0;
    if (len == 0) {
        return 0;
    }

    mutex_lock_interruptible(&sbuffer->mutex);

    if (list_empty(&sbuffer->list)) {
        if (!(new_node = bperf_sbuffer_node_new())) {
            return -ENOMEM;
        }
        list_add(&new_node->list, &sbuffer->list);
    }

    while (true) {
        last_node = container_of(sbuffer->list.prev, struct bperf_sbuffer_node, list);
        space_left = BPERF_SBUFFER_MAX_SZ - last_node->size;
        amt_to_write = MIN(len - ret, space_left);

        if (amt_to_write > 0) {
            memcpy(bperf_sbuffer_node_data(last_node) + last_node->size, src + ret, amt_to_write);
            ret += amt_to_write;
            sbuffer->size += amt_to_write;
            last_node->size += amt_to_write;
        }
        if (ret == len) {
            goto out;
        }

        if (!(new_node = bperf_sbuffer_node_new())) {
            ret = -ENOMEM;
            goto out;
        }
        list_add_tail(&new_node->list, &sbuffer->list);
    }

out:
    mutex_unlock(&sbuffer->mutex);
    if (ret > 0) {
        wake_up_interruptible(&sbuffer->waitq);
    }
    return ret;
}

/**
 * @brief Read upto len bytes of data from the buffer into the destination (user-space)
 */
static ssize_t bperf_sbuffer_read(struct bperf_sbuffer *sbuffer, char __user *dest, size_t len, bool blocking)
{
    ssize_t amt_data_in_node, amt_to_write, ret = 0;
    struct list_head *ll_node;
    struct bperf_sbuffer_node *node;

    if (len == 0) {
        return 0;
    }

    mutex_lock_interruptible(&sbuffer->mutex);

    // Block while there isn't data to read
    while (sbuffer->size == 0) {
        mutex_unlock(&sbuffer->mutex);
        if (!blocking) {
            return -EAGAIN;
        }
        if (wait_event_interruptible(sbuffer->waitq, sbuffer->size > 0)) {
            return -ERESTARTSYS;
        }
        mutex_lock_interruptible(&sbuffer->mutex);
    }

    ll_node = sbuffer->list.next;
    while (ll_node != &sbuffer->list) {
        node = container_of(ll_node, struct bperf_sbuffer_node, list);
        amt_data_in_node = node->size - node->start;
        amt_to_write = MIN(amt_data_in_node, len - ret);

        if (amt_to_write == 0) {
            if (node->size == BPERF_SBUFFER_MAX_SZ) {
                ll_node = ll_node->next;
                bperf_sbuffer_node_free(node);
                continue;
            } else {
                break;
            }
        } else {
            if (copy_to_user(dest + ret, bperf_sbuffer_node_data(node) + node->start, amt_to_write)) {
                ret = -EFAULT;
                goto out;
            }
            node->start += amt_to_write;
            ret += amt_to_write;
            sbuffer->size -= amt_to_write;
        }
        if (ret == len) {
            goto out;
        }
    }

out:
    mutex_unlock(&sbuffer->mutex);
    return ret;
}

// ======== Synchronized data buffer ========

/**
 * @brief Waitqueue for threads waiting to write data
 */
static DECLARE_WAIT_QUEUE_HEAD(BPERF_WQ);

/**
 * @brief Static buffer before writing to string buffer
 */
#define SNPRINTF_BUFSZ 4096
static char SNPRINTF_BUFFER[SNPRINTF_BUFSZ];
static int SNPRINTF_WRITTEN = 0;

/**
 * @brief Write formatted data to static staging buffer
 */
static void bperf_snprintf(const char *fmt, ...)
{
    va_list args;
    int ret = 0;
    while (true) {
        va_start(args, fmt);
        ret = vsnprintf(SNPRINTF_BUFFER + SNPRINTF_WRITTEN, SNPRINTF_BUFSZ - SNPRINTF_WRITTEN, fmt, args);
        if (ret + SNPRINTF_WRITTEN >= SNPRINTF_BUFSZ) {
            ret = bperf_sbuffer_write(&SBUFFER, SNPRINTF_BUFFER, SNPRINTF_WRITTEN);
            SNPRINTF_WRITTEN -= ret;
            if (SNPRINTF_WRITTEN > 0) {
                memcpy(SNPRINTF_BUFFER, SNPRINTF_BUFFER + ret, SNPRINTF_WRITTEN);
            }
            va_end(args);
        } else {
            SNPRINTF_WRITTEN += ret;
            va_end(args);
            break;
        }
    }
}

/**
 * @brief Flush staged string to buffer
 */
static void bperf_snprintf_flush(void)
{
    int ret;
    while (SNPRINTF_WRITTEN > 0) {
        ret = bperf_sbuffer_write(&SBUFFER, SNPRINTF_BUFFER, SNPRINTF_WRITTEN);
        SNPRINTF_WRITTEN -= ret;
        if (SNPRINTF_WRITTEN > 0) {
            memcpy(SNPRINTF_BUFFER, SNPRINTF_BUFFER + ret, SNPRINTF_WRITTEN);
        }
    }
}

/**
 * @brief A data node for a single thread
 */
struct bperf_dbuffer_thread {
    uint64_t perfevtsel_bak[BPERF_MAX_PMC]; /* Back up perfevtsel registers */
    uint64_t fixed_ctrl_bak;                /* Back up fixed ctrl register */
    uint64_t global_ctrl_bak;               /* Back up perf global ctrl register */
    uint64_t timestamp;                     /* Timestamp in nanoseconds */
    uint64_t last_pmc[BPERF_MAX_PMC];       /* Last PMCx reading */
    uint64_t last_fixed[BPERF_MAX_FIXED];   /* Last fixed counter reading */
    uint64_t pmc[BPERF_MAX_PMC];            /* PMCx increment */
    uint64_t fixed[BPERF_MAX_FIXED];        /* fixed counter increment */
    bool     has_pmc[BPERF_MAX_PMC];        /* Whether data for this PMCx is present */
    bool     has_fixed[BPERF_MAX_FIXED];    /* Whether data for this fixed counter is present */
};

/**
 * @brief A variable-sized data node for a single timestamp
 */
static struct bperf_dbuffer {
    size_t                      num_threads; /* Number of threads */
    atomic_t                    to_check_in; /* Number of threads to check in */
    bool                        *checked_in; /* Whether the given thread has checked in its data */
    struct bperf_dbuffer_thread *data;       /* Per-thread data */
} DBUFFER = { 0 };

/**
 * @brief Initialize buffer
 */
static int bperf_dbuffer_init(struct bperf_dbuffer *db, size_t nthreads)
{
    db->data = kvmalloc(nthreads * sizeof(struct bperf_dbuffer_thread), GFP_KERNEL);
    if (!db->data || IS_ERR(db->data)) {
        printk(KERN_ALERT "bperf: Failed to initialize data buffer: kvmalloc failed\n");
        return -ENOMEM;
    }
    db->checked_in = kvmalloc(nthreads * sizeof(bool), GFP_KERNEL);
    if (!db->checked_in || IS_ERR(db->checked_in)) {
        kvfree(db->data);
        printk(KERN_ALERT "bperf: Failed to initialize checked_in array: kvmalloc failed\n");
        return -ENOMEM;
    }
    memset(db->checked_in, 0, nthreads * sizeof(bool));
    db->num_threads = nthreads;
    atomic_set(&db->to_check_in, db->num_threads);
    return 0;
}

/**
 * @brief Free memory for buffer
 */
static void bperf_dbuffer_fini(struct bperf_dbuffer *dbuffer)
{
    kvfree(dbuffer->data);
    kvfree(dbuffer->checked_in);
}

/**
 * @brief Write measured data to string buffer
 */
static void bperf_dbuffer_to_string(struct bperf_dbuffer *dbuffer, size_t thread_id)
{
    size_t i, j;
    uint64_t timestamp = dbuffer->data[thread_id].timestamp;

    bperf_snprintf("%llu\n", timestamp);

    for (i = 0; i < STATE.num_pmc; i++) {
        if (STATE.pmc_id[i] == DISABLED) {
            continue;
        }
        bperf_snprintf("%s ", bperf_get_event_name(STATE.pmc_id[i]));
        for (j = 0; j < dbuffer->num_threads; j++) {
            if (!dbuffer->data[j].has_pmc[i]) {
                continue;
            }
            bperf_snprintf("%llu ", dbuffer->data[j].pmc[i]);
        }
        bperf_snprintf("\n");
    }

    for (i = 0; i < STATE.num_fixed; i++) {
        bperf_snprintf("%s ", bperf_get_fixed_ctr_name(i));
        for (j = 0; j < dbuffer->num_threads; j++) {
            if (!dbuffer->data[j].has_fixed[i]) {
                continue;
            }
            bperf_snprintf("%llu ", dbuffer->data[j].fixed[i]);
        }
        bperf_snprintf("\n");
    }

    bperf_snprintf("========\n");

    bperf_snprintf_flush();
}

/**
 * @brief Notify that thread has finished writing data, and block if required
 */
static void bperf_dbuffer_thread_checkin(struct bperf_dbuffer *dbuffer, size_t thread_id)
{
    if (thread_id >= dbuffer->num_threads) {
        printk(KERN_ALERT "bperf: Invalid thread id: %lu: max: %lu\n", thread_id, dbuffer->num_threads);
        return;
    }
    // printk(KERN_INFO "bperf: Thread %lu check-in start\n", thread_id);
    if (dbuffer->checked_in[thread_id]) {
        wait_event_interruptible(BPERF_WQ, kthread_should_stop() || !dbuffer->checked_in[thread_id]);
        if (kthread_should_stop()) {
            return;
        }
    }
    // printk(KERN_INFO "bperf: Thread %lu check-in done: checked_in: %d: atomic: %u\n", thread_id, dbuffer->checked_in[thread_id], atomic_read(&dbuffer->to_check_in));
    dbuffer->checked_in[thread_id] = true;

    if (atomic_dec_and_test(&dbuffer->to_check_in)) {
        // printk(KERN_INFO "bperf: Thread %lu writing to sbuffer\n", thread_id);
        if (STATE.enabled) {
            bperf_dbuffer_to_string(dbuffer, thread_id);
        } else {
            bperf_sbuffer_clear(&SBUFFER);
        }
        atomic_set(&dbuffer->to_check_in, dbuffer->num_threads);
        memset(dbuffer->checked_in, 0, dbuffer->num_threads * sizeof(bool));
        wake_up_interruptible(&BPERF_WQ);
    }
}

// ======== Module logic ========

/**
 * @brief Dummy llseek function. Basically we don't support seeking
 */
static loff_t bperf_llseek(struct file *filp, loff_t off, int whence)
{
    return -ESPIPE; /* unseekable */
}

/**
 * @brief Open the device and maintain a count of how many times it has been opened
 */
static int bperf_open(struct inode *inode, struct file *filp)
{
    printk(KERN_INFO "bperf: Device file opened\n");
    return 0;
}

/**
 * @brief Decrement count of number of instances of the file being opened
 */
static int bperf_release(struct inode *inode, struct file *filp)
{
    printk(KERN_INFO "bperf: Device file closed\n");
    return 0;
}

/**
 * @brief Read the file
 */
static ssize_t bperf_read(struct file *filp, char __user *buffer, size_t size, loff_t *f_pos)
{
    ssize_t ret = bperf_sbuffer_read(&SBUFFER, buffer, size, (filp->f_flags & O_NONBLOCK) == 0);
    if (ret > 0) {
        *f_pos += ret;
    }
    return ret;
}

/**
 * @brief File operations for /dev/bperf files
 */
static struct file_operations bperf_fops = {
    .owner   = THIS_MODULE,
    .llseek  = bperf_llseek,
    .open    = bperf_open,
    .release = bperf_release,
    .read    = bperf_read,
};

/**
 * @brief Identify processor
 */
static void bperf_identify_processor(void)
{
    uint32_t eax = 1, ebx = 0, ecx = 0, edx = 0, stepping, ext_model;
    bperf_cpuid(&eax, &ebx, &ecx, &edx);
    stepping = eax & 0xf;
    STATE.model = (eax >> 4) & 0xf;
    STATE.family = (eax >> 8) & 0xf;
    if (STATE.family == 0x06 || STATE.family == 0x0f) {
        ext_model = (eax >> 16) & 0x0f;
        STATE.model = (ext_model << 4) + STATE.model;
    }
    if (STATE.family == 0x0f) {
        STATE.family += (eax >> 20) & 0xff;
    }
    printk(KERN_INFO "bperf: CPU family: %#x, model: %#x, stepping: %u\n", STATE.family, STATE.model, stepping);
}

/**
 * @brief Get architectural performance monitoring capabilities
 */
static void bperf_get_arch_perfmon_capabilities(void)
{
    uint32_t eax = 0x0a, ebx = 0, ecx = 0, edx = 0, bvsz;
    bperf_cpuid(&eax, &ebx, &ecx, &edx);

    STATE.arch_perf_ver = eax & 0xff;
    STATE.num_pmc       = (eax >> 8) & 0xff;
    STATE.num_pmc       = MIN(STATE.num_pmc, BPERF_MAX_PMC);
    STATE.ctr_width     = (eax >> 16) & 0xff;
    bvsz                = (eax >> 24) & 0xff;

    STATE.ev_core_cycle        = bvsz > 0 && !(ebx & (1 << 0));
    STATE.ev_inst_retired      = bvsz > 1 && !(ebx & (1 << 1));
    STATE.ev_ref_cycles        = bvsz > 2 && !(ebx & (1 << 2));
    STATE.ev_llc_ref           = bvsz > 3 && !(ebx & (1 << 3));
    STATE.ev_llc_miss          = bvsz > 4 && !(ebx & (1 << 4));
    STATE.ev_branch_retired    = bvsz > 5 && !(ebx & (1 << 5));
    STATE.ev_branch_mispredict = bvsz > 6 && !(ebx & (1 << 6));

    if (STATE.arch_perf_ver > 1) {
        STATE.num_fixed     = edx & 0x1f;
        STATE.num_fixed     = MIN(STATE.num_fixed, BPERF_MAX_FIXED);
        STATE.fix_ctr_width = (edx >> 5) & 0xff;
    }

    printk(KERN_INFO "bperf: Perf ver: %u, num ctr: %u, ctr width: %d\n"
             "       EBX: %#x\n"
             "       core cycles: %u, inst ret: %u, ref cycles: %u, llc ref: %u,"
             " llc miss: %u, branch ret: %u, branch mispredict: %u\n"
             "       num fixed ctr: %u, fix ctr size: %u\n",
             STATE.arch_perf_ver, STATE.num_pmc, STATE.ctr_width, ebx, STATE.ev_core_cycle,
             STATE.ev_inst_retired, STATE.ev_ref_cycles, STATE.ev_llc_miss, STATE.ev_llc_miss,
             STATE.ev_branch_retired, STATE.ev_branch_mispredict, STATE.num_fixed,
             STATE.fix_ctr_width);
}

/**
 * @brief Fill default values for module state
 */
static void bperf_fill_state_defaults(void)
{
    STATE.sample_interval = BPERF_DEFAULT_INTERVAL;
}

/**
 * @brief Setup or disable counting on a single PMC for a single thread
 */
static bool bperf_thread_setup_pmc(size_t thread_id, size_t pmc_id)
{
    uint64_t val;
    struct bperf_dbuffer_thread *thread_state;
    const struct bperf_event *ev;

    thread_state = &DBUFFER.data[thread_id];
    val = thread_state->perfevtsel_bak[pmc_id];
    val &= PERFEVTSEL_RESERVED;
    val |= PERFEVTSEL_FLAG_OS | PERFEVTSEL_FLAG_USR | PERFEVTSEL_FLAG_ENABLE;
    if (STATE.arch_perf_ver >= 3) {
        val &= ~PERFEVTSEL_FLAG_ANYTHRD;
    }
    if (!(ev = bperf_get_arch_event(STATE.pmc_id[pmc_id], STATE.family, STATE.model))) {
        thread_state->has_pmc[pmc_id] = false;
        return false;
    }
    val |= perfevtsel_from_ev(ev);
    bperf_wrmsr(MSR_PERFEVTSEL(pmc_id), val);
    thread_state->last_pmc[pmc_id] = bperf_rdmsr(MSR_PMC(pmc_id));
    thread_state->has_pmc[pmc_id] = true;
    return true;
}

/**
 * @brief Thread function for polling counters
 */
static int bperf_thread_function(void *arg_thread_id)
{
    uint32_t i;
    uint64_t r, w, ctrl;
    size_t thread_id;
    struct bperf_dbuffer_thread *thread_state;
    thread_id = (size_t) arg_thread_id;
    thread_state = &DBUFFER.data[thread_id];
    memset(thread_state, 0, sizeof(struct bperf_dbuffer_thread));

    // Get current state of PERF_GLOBAL_CTRL and disable monitoring
    ctrl = thread_state->global_ctrl_bak = bperf_rdmsr(MSR_PERF_GLOBAL_CTRL);
    ctrl &= GLOBAL_CTRL_RESERVED;
    bperf_wrmsr(MSR_PERF_GLOBAL_CTRL, ctrl);

    // Get current state of PERFEVTSEL and PMC MSR. Set counting as enabled
    for (i = 0; i < STATE.num_pmc; i++) {
        thread_state->perfevtsel_bak[i] = bperf_rdmsr(MSR_PERFEVTSEL(i));
        if (bperf_thread_setup_pmc(thread_id, i)) {
            ctrl |= GLOBAL_CTRL_PMC(i);
        }
    }

    // Get current state of fixed counters
    w = thread_state->fixed_ctrl_bak = bperf_rdmsr(MSR_FIXED_CTR_CTRL);
    w &= FIXED_CTRL_RESERVED;
    for (i = 0; i < STATE.num_fixed; i++) {
        w |= FIXED_CTRL_EN(i);
        ctrl |= GLOBAL_CTRL_FIXED(i);
        thread_state->last_fixed[i] = bperf_rdmsr(MSR_FIXED_CTR(i));
        thread_state->has_fixed[i] = true;
    }
    bperf_wrmsr(MSR_FIXED_CTR_CTRL, w);

    // Enable performance monitoring
    if (STATE.enabled) {
        bperf_wrmsr(MSR_PERF_GLOBAL_CTRL, ctrl);
    }

    while (!kthread_should_stop()) {
        if (!STATE.enabled) {
            ctrl &= GLOBAL_CTRL_RESERVED;
            bperf_wrmsr(MSR_PERF_GLOBAL_CTRL, ctrl);
            wait_event_interruptible(ENABLED_WQ, kthread_should_stop() || STATE.enabled);
            if (kthread_should_stop()) {
                break;
            }
            for (i = 0; i < STATE.num_fixed; i++) {
                ctrl |= GLOBAL_CTRL_FIXED(i);
            }
            for (i = 0; i < STATE.num_pmc; i++) {
                if (bperf_thread_setup_pmc(thread_id, i)) {
                    ctrl |= GLOBAL_CTRL_PMC(i);
                }
            }
            bperf_wrmsr(MSR_PERF_GLOBAL_CTRL, ctrl);
        }
        msleep(STATE.sample_interval);
        thread_state->timestamp = ktime_get_ns();
        // printk(KERN_INFO "bperf: Thread function: %u, ts: %#llx\n", smp_processor_id(), thread_state->timestamp);
        for (i = 0; i < STATE.num_pmc; i++) {
            r = bperf_rdmsr(MSR_PMC(i));
            if (r < thread_state->last_pmc[i]) {
                thread_state->pmc[i] = 0;
            } else {
                thread_state->pmc[i] = r - thread_state->last_pmc[i];
            }
            thread_state->last_pmc[i] = r;
        }
        for (i = 0; i < STATE.num_fixed; i++) {
            r = bperf_rdmsr(MSR_FIXED_CTR(i));
            if (r < thread_state->last_fixed[i]) {
                thread_state->fixed[i] = 0;
            } else {
                thread_state->fixed[i] = r - thread_state->last_fixed[i];
            }
            thread_state->last_fixed[i] = r;
        }
        bperf_dbuffer_thread_checkin(&DBUFFER, thread_id);
    }

    // Restore performance monitor settings
    ctrl = bperf_rdmsr(MSR_PERF_GLOBAL_CTRL);
    ctrl &= GLOBAL_CTRL_RESERVED;
    bperf_wrmsr(MSR_PERF_GLOBAL_CTRL, ctrl);
    for (i = 0; i < STATE.num_pmc; i++) {
        bperf_wrmsr(MSR_PERFEVTSEL(i), thread_state->perfevtsel_bak[i]);
    }
    bperf_wrmsr(MSR_FIXED_CTR_CTRL, thread_state->fixed_ctrl_bak);
    bperf_wrmsr(MSR_PERF_GLOBAL_CTRL, thread_state->global_ctrl_bak);

    return 0;
}

/**
 * @brief The kernel module initialization function
 */
static int __init bperf_init(void)
{
    int ret;
    size_t i, j;

    printk(KERN_INFO "bperf: Loading...\n");
    bperf_identify_processor();
    bperf_get_arch_perfmon_capabilities();
    bperf_fill_state_defaults();
    if (STATE.arch_perf_ver < BPERF_MIN_ARCH || STATE.num_pmc == 0) {
        printk(KERN_ALERT "bperf: Not enough support for performance monitoring\n");
        return -1;
    }

    // Allocate memory for string buffer
    if ((ret = bperf_sbuffer_init(&SBUFFER)) < 0) {
        printk(KERN_ALERT "bperf: Failed to allocate string buffer\n");
        return ret;
    }

    // Try to dynamically allocate a major number for the device
    if ((ret = alloc_chrdev_region(&STATE.dev, 0, 1, BPERF_NAME)) < 0) {
        printk(KERN_ALERT "bperf: Could not allocate major number\n");
        goto error_major_number;
    }
    printk(KERN_INFO "bperf: device = %d,%d\n", MAJOR(STATE.dev), MINOR(STATE.dev));

    // Create class struct
    STATE.class = class_create(THIS_MODULE, BPERF_NAME);
    if (!STATE.class || IS_ERR(STATE.class)) {
        printk(KERN_ALERT "bperf: Failed to register device class\n");
        ret = PTR_ERR(STATE.class);
        goto error_class;
    }

    // Create device
    STATE.device = device_create(STATE.class, NULL, STATE.dev, NULL, "bperf");
    if (!STATE.device || IS_ERR(STATE.device)) {
        printk(KERN_ALERT "bperf: Failed to create device file\n");
        ret = PTR_ERR(STATE.device);
        goto error_device;
    }

    // Initialize char device structure
    cdev_init(&STATE.cdev, &bperf_fops);
    STATE.cdev.owner = THIS_MODULE;
    STATE.cdev.ops = &bperf_fops;
    if ((ret = cdev_add(&STATE.cdev, STATE.dev, 1))) {
        printk(KERN_ALERT "bperf: Failed to add char device\n");
        goto error_cdev;
    }

    // Initialize kobject and attributes
    STATE.kobj = kobject_create_and_add("bperf", kernel_kobj);
    if (!STATE.kobj || IS_ERR(STATE.kobj)) {
        printk(KERN_ALERT "bperf: Failed to create kobject\n");
        ret = PTR_ERR(STATE.kobj);
        goto error_kobj;
    }
    if ((ret = sysfs_create_file(STATE.kobj, &num_cores_attr.attr))) {
        printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
        goto error_cores_attr;
    }
    if ((ret = sysfs_create_file(STATE.kobj, &num_pmc_attr.attr))) {
        printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
        goto error_pmc_attr;
    }
    if ((ret = sysfs_create_file(STATE.kobj, &num_fixed_attr.attr))) {
        printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
        goto error_fixed_attr;
    }
    if ((ret = sysfs_create_file(STATE.kobj, &arch_perf_ver_attr.attr))) {
        printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
        goto error_perf_ver_attr;
    }
    if ((ret = sysfs_create_file(STATE.kobj, &enabled_attr.attr))) {
        printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
        goto error_enabled_attr;
    }
    if ((ret = sysfs_create_file(STATE.kobj, &sample_interval_attr.attr))) {
        printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
        goto error_sample_interval_attr;
    }
    if ((ret = sysfs_create_file(STATE.kobj, &cpu_family_attr.attr))) {
        printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
        goto error_cpu_family_attr;
    }
    if ((ret = sysfs_create_file(STATE.kobj, &cpu_model_attr.attr))) {
        printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
        goto error_cpu_model_attr;
    }
    for (j = 0; j < STATE.num_pmc; j++) {
        if ((ret = sysfs_create_file(STATE.kobj, &pmc_attrs[j].attr))) {
            printk(KERN_ALERT "bperf: Failed to create sysfs attribute\n");
            goto error_pmc_attrs;
        }
    }

    // Allocate buffers for all threads
    // FIXME: Handle non-linear core numbers
    // FIXME: Handle CPU hotplug
    STATE.num_threads = num_online_cpus();
    printk(KERN_INFO "bperf: Num online CPUs: %lu\n", STATE.num_threads);
    if ((ret = bperf_dbuffer_init(&DBUFFER, STATE.num_threads)) < 0) {
        goto error_dbuffer;
    }

    // Spawn kernel thread per logical core
    STATE.thread_ptr = kvmalloc(STATE.num_threads * sizeof(struct task_struct*), GFP_KERNEL);
    if (!STATE.thread_ptr || IS_ERR(STATE.thread_ptr)) {
        printk(KERN_ALERT "bperf: Failed to allocate array of thread pointers\n");
        ret = PTR_ERR(STATE.thread_ptr);
        goto error_thread_alloc;
    }

    for (i = 0; i < STATE.num_threads; i++) {
        STATE.thread_ptr[i] = kthread_create(bperf_thread_function, (void*) i, "bperf_thread");
        if (!STATE.thread_ptr[i] || IS_ERR(STATE.thread_ptr[i])) {
            printk(KERN_ALERT "bperf: Failed to spawn worker thread\n");
            ret = PTR_ERR(STATE.thread_ptr[i]);
            goto error_thread_create;
        }
        kthread_bind(STATE.thread_ptr[i], i);
    }
    for (i = 0; i < STATE.num_threads; i++) {
        wake_up_process(STATE.thread_ptr[i]);
    }

    // Success
    printk(KERN_INFO "bperf: Loaded!\n");
    return 0;

error_thread_create:
    kvfree(STATE.thread_ptr);
error_thread_alloc:
    bperf_dbuffer_fini(&DBUFFER);
error_dbuffer:
    j = STATE.num_pmc - 1;
error_pmc_attrs:
    for (i = 0; i <= j; i++) {
        sysfs_remove_file(STATE.kobj, &pmc_attrs[i].attr);
    }
    sysfs_remove_file(STATE.kobj, &cpu_model_attr.attr);
error_cpu_model_attr:
    sysfs_remove_file(STATE.kobj, &cpu_family_attr.attr);
error_cpu_family_attr:
    sysfs_remove_file(STATE.kobj, &sample_interval_attr.attr);
error_sample_interval_attr:
    sysfs_remove_file(STATE.kobj, &enabled_attr.attr);
error_enabled_attr:
    sysfs_remove_file(STATE.kobj, &arch_perf_ver_attr.attr);
error_perf_ver_attr:
    sysfs_remove_file(STATE.kobj, &num_fixed_attr.attr);
error_fixed_attr:
    sysfs_remove_file(STATE.kobj, &num_pmc_attr.attr);
error_pmc_attr:
    sysfs_remove_file(STATE.kobj, &num_cores_attr.attr);
error_cores_attr:
    kobject_put(STATE.kobj);
error_kobj:
    cdev_del(&STATE.cdev);
error_cdev:
    device_destroy(STATE.class, STATE.dev);
error_device:
    class_destroy(STATE.class);
error_class:
    unregister_chrdev_region(STATE.dev, 1);
error_major_number:
    bperf_sbuffer_fini(&SBUFFER);
    return ret;
}

/**
 * @brief The kernel module cleanup function
 */
static void __exit bperf_exit(void)
{
    size_t i;
    printk(KERN_INFO "bperf: Unloading...\n");

    for (i = 0; i < STATE.num_threads; i++) {
        kthread_stop(STATE.thread_ptr[i]);
    }
    kvfree(STATE.thread_ptr);
    bperf_dbuffer_fini(&DBUFFER);
    for (i = 0; i < STATE.num_pmc; i++) {
        sysfs_remove_file(STATE.kobj, &pmc_attrs[i].attr);
    }
    sysfs_remove_file(STATE.kobj, &cpu_model_attr.attr);
    sysfs_remove_file(STATE.kobj, &cpu_family_attr.attr);
    sysfs_remove_file(STATE.kobj, &sample_interval_attr.attr);
    sysfs_remove_file(STATE.kobj, &enabled_attr.attr);
    sysfs_remove_file(STATE.kobj, &arch_perf_ver_attr.attr);
    sysfs_remove_file(STATE.kobj, &num_fixed_attr.attr);
    sysfs_remove_file(STATE.kobj, &num_pmc_attr.attr);
    sysfs_remove_file(STATE.kobj, &num_cores_attr.attr);
    kobject_put(STATE.kobj);
    cdev_del(&STATE.cdev);
    device_destroy(STATE.class, STATE.dev);
    class_destroy(STATE.class);
    unregister_chrdev_region(STATE.dev, 1);
    bperf_sbuffer_fini(&SBUFFER);

    printk(KERN_INFO "bperf: Unloaded!\n");
}

/**
 * @brief Identify the initialization and cleanup functions
 */
module_init(bperf_init);
module_exit(bperf_exit);

/* Linux kernel stuff */
MODULE_LICENSE(BPERF_LICENSE);
MODULE_AUTHOR(BPERF_AUTHOR);
MODULE_DESCRIPTION(BPERF_DESC);
MODULE_VERSION(BPERF_VERSION);
