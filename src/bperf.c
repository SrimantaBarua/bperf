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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <asm/smp.h>

#define BPERF_NAME      "bperf"
#define BPERF_LICENSE   "GPL"
#define BPERF_AUTHOR    "Srimanta Barua <srimanta.barua1@gmail.com>"
#define BPERF_DESC      "Kernel module for high frequency counter sampling on x86_64 systems"
#define BPERF_VERSION   "0.1"
#define BPERF_HZ        5
#define BPERF_MIN_ARCH  2
#define BPERF_MSLEEP    (1000 / BPERF_HZ)

#define BPERF_MAX_PMC   4
#define BPERF_MAX_FIXED 3

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#include "hardware.c"
#include "sbuffer.c"

/**
 * @brief Global module state
 */
static struct bperf_state {
	/* Kernel state */
	dev_t         dev;         /* Stores the device number */
	struct class  *class;      /* The device-driver class struct */
	struct device *device;     /* The device-driver device struct */
	struct cdev   cdev;        /* Char device structure */
	/* Module information */
	size_t             open_count;   /* Current open count for device file */
	size_t             num_threads;  /* Number of threads we spawned */
	struct task_struct **thread_ptr; /* Pointers to task struct for kernel thread */
	/* Performance monitoring capabilities */
	uint32_t arch_perf_ver; /* Version ID of architectural performance monitoring */
	uint32_t num_ctr;       /* Number of general purpose counters per logical processor */
	uint32_t ctr_width;     /* Bit width of general purpose counters */
	uint32_t num_fix_ctr;   /* Number of fixed function counters */
	uint32_t fix_ctr_width; /* Bit width of fixed function counters */
	/* Whether specific events are available */
	bool ev_core_cycle;        /* Core cycle event available */
	bool ev_inst_retired;      /* Instruction retired event available */
	bool ev_ref_cycles;        /* Reference cycles event available */
	bool ev_llc_ref;           /* LLC reference event available */
	bool ev_llc_miss;          /* LLC miss event available */
	bool ev_branch_retired;    /* Branch instruction retired event available */
	bool ev_branch_mispredict; /* Branch mispredict retired event available */
} STATE = { 0 };

#include "dbuffer.c"

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
	struct bperf_state *state = container_of(inode->i_cdev, struct bperf_state, cdev);
	state->open_count++;
	filp->private_data = state;
	printk(KERN_INFO "bperf: Device file opened\n");
	return 0;
}

/**
 * @brief Decrement count of number of instances of the file being opened
 */
static int bperf_release(struct inode *inode, struct file *filp)
{
	struct bperf_state *state = container_of(inode->i_cdev, struct bperf_state, cdev);
	state->open_count--;
	printk(KERN_INFO "bperf: Device file closed\n");
	return 0;
}

/**
 * @brief Read the file
 */
static ssize_t bperf_read(struct file *filp, char __user *buffer, size_t size, loff_t *f_pos)
{
	struct bperf_state *state = filp->private_data;
	ssize_t ret = bperf_sbuffer_read(&SBUFFER, buffer, size);
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
	uint32_t eax = 1, ebx = 0, ecx = 0, edx = 0, stepping, model, family, ext_model;
	bperf_cpuid(&eax, &ebx, &ecx, &edx);
	stepping = eax & 0xf;
	model = (eax >> 4) & 0xf;
	family = (eax >> 8) & 0xf;
	if (family == 0x06 || family == 0x0f) {
		ext_model = (eax >> 16) & 0x0f;
		model = (ext_model << 4) + model;
	}
	if (family == 0x0f) {
		family += (eax >> 20) & 0xff;
	}
	printk(KERN_INFO "bperf: CPU family: %#x, model: %u, stepping: %u\n", family, model, stepping);
}

/**
 * @brief Get architectural performance monitoring capabilities
 */
static void bperf_get_arch_perfmon_capabilities(void)
{
	uint32_t eax = 0x0a, ebx = 0, ecx = 0, edx = 0, bvsz;
	bperf_cpuid(&eax, &ebx, &ecx, &edx);

	STATE.arch_perf_ver = eax & 0xff;
	STATE.num_ctr       = (eax >> 8) & 0xff;
	STATE.num_ctr       = MAX(STATE.num_ctr, BPERF_MAX_PMC);
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
		STATE.num_fix_ctr = edx & 0x1f;
		STATE.num_fix_ctr = MAX(STATE.num_fix_ctr, BPERF_MAX_FIXED);
		STATE.fix_ctr_width = (edx >> 5) & 0xff;
	}

	printk(KERN_INFO "bperf: Perf ver: %u, num ctr: %u, ctr width: %d\n"
			 "       EBX: %#x\n"
			 "       core cycles: %u, inst ret: %u, ref cycles: %u, llc ref: %u,"
			 " llc miss: %u, branch ret: %u, branch mispredict: %u\n"
			 "       num fixed ctr: %u, fix ctr size: %u\n",
			 STATE.arch_perf_ver, STATE.num_ctr, STATE.ctr_width,
			 ebx, STATE.ev_core_cycle, STATE.ev_inst_retired, STATE.ev_ref_cycles,
			 STATE.ev_llc_miss, STATE.ev_llc_miss, STATE.ev_branch_retired,
			 STATE.ev_branch_mispredict, STATE.num_fix_ctr, STATE.fix_ctr_width);
}

/**
 * @brief Thread function for polling counters
 */
static int bperf_thread_function(void *arg_thread_id)
{
	// The events that we want per PMC
	// FIXME: Align with BPERF_MAX_FIXED and BPERF_MAX_PMC
	static uint64_t pmc_events[4] = {
		PERFEVTSEL_CORE_CYCLES,
		PERFEVTSEL_LLC_MISS,
		PERFEVTSEL_BRANCH_MISS,
		PERFEVTSEL_LLC_REF
	};

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
	for (i = 0; i < STATE.num_ctr; i++) {
		w = thread_state->perfevtsel_bak[i] = bperf_rdmsr(MSR_PERFEVTSEL(i));
		w &= PERFEVTSEL_RESERVED;
		if (STATE.arch_perf_ver >= 3) {
			w &= ~PERFEVTSEL_FLAG_ANYTHRD;
		}
		w |= PERFEVTSEL_FLAGS_SANE | pmc_events[i];
		bperf_wrmsr(MSR_PERFEVTSEL(i), w);
		// Get current value of the PMC
		thread_state->last_pmc[i] = bperf_rdmsr(MSR_PMC(i));
		thread_state->has_pmc[i] = true;
		ctrl |= GLOBAL_CTRL_PMC(i);
	}

	// Get current state of fixed counters
	w = thread_state->fixed_ctrl_bak = bperf_rdmsr(MSR_FIXED_CTR_CTRL);
	w &= FIXED_CTRL_RESERVED;
	for (i = 0; i < STATE.num_fix_ctr; i++) {
		w |= FIXED_CTRL_EN(i);
		ctrl |= GLOBAL_CTRL_FIXED(i);
		thread_state->last_fixed[i] = bperf_rdmsr(MSR_FIXED_CTR(i));
		thread_state->has_fixed[i] = true;
	}
	bperf_wrmsr(MSR_FIXED_CTR_CTRL, w);

	// Enable performance monitoring
	bperf_wrmsr(MSR_PERF_GLOBAL_CTRL, ctrl);

	while (!kthread_should_stop()) {
		msleep(BPERF_MSLEEP);
		thread_state->timestamp = ktime_get_ns();
		printk(KERN_INFO "bperf: Thread function: %u, ts: %#llx\n", smp_processor_id(), thread_state->timestamp);
		for (i = 0; i < STATE.num_ctr; i++) {
			r = bperf_rdmsr(MSR_PMC(i));
			if (r < thread_state->last_pmc[i]) {
				thread_state->pmc[i] = 0;
			} else {
				thread_state->pmc[i] = r - thread_state->last_pmc[i];
			}
			thread_state->last_pmc[i] = r;
		}
		for (i = 0; i < STATE.num_fix_ctr; i++) {
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
	for (i = 0; i < STATE.num_ctr; i++) {
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
	size_t i;

	printk(KERN_INFO "bperf: Loading...\n");
	bperf_identify_processor();
	bperf_get_arch_perfmon_capabilities();
	if (STATE.arch_perf_ver < BPERF_MIN_ARCH) {
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
