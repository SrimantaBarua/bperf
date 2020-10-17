/**
 * @file    bperf.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    27 September 2020
 * @version 0.1
 * @brief A kernel module for high frequency counter sampling on x86_64 systems
 */

#include <asm/smp.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define BPERF_NAME      "bperf"
#define BPERF_LICENSE   "GPL"
#define BPERF_AUTHOR    "Srimanta Barua <srimanta.barua1@gmail.com>"
#define BPERF_DESC      "Kernel module for high frequency counter sampling on x86_64 systems"
#define BPERF_VERSION   "0.1"
#define BPERF_DEV_COUNT 1
#define BPERF_BLK_SZ    2048

#define MIN(x, y) ((x) < (y) ? (x) : (y))

/* MSR numbers */
#define MSR_IA32_PMC(x)        (0xc1U + (x))
#define MSR_IA32_PERFEVTSEL(x) (0x186U + (x))

/* Architectural performance monitoring event select and umask */
#define PERFEVTSEL_CORE_CYCLES 0x003cUL
#define PERFEVTSEL_INST_RET    0x00c0UL
#define PERFEVTSEL_REF_CYCLES  0x013cUL
#define PERFEVTSEL_LLC_REF     0x4f2eUL
#define PERFEVTSEL_LLC_MISS    0x412eUL
#define PERFEVTSEL_BRANCH_RET  0x00c4UL
#define PERFEVTSEL_BRANCH_MISS 0x00c5UL
/* Architectural performance monitoring flags */
#define PERFEVTSEL_RESERVED    0xffffffff00280000UL
#define PERFEVTSEL_FLAG_USR    0x10000UL
#define PERFEVTSEL_FLAG_OS     0x20000UL
#define PERFEVTSEL_FLAG_ENABLE 0x400000UL
#define PERFEVTSEL_FLAGS_SANE  (PERFEVTSEL_FLAG_USR | PERFEVTSEL_FLAG_OS | PERFEVTSEL_FLAG_ENABLE)

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

/**
 * @brief Linked list node of circular string buffer
 *
 * Total size of a node is BPERF_BLK_SZ bytes. This size includes this "header" struct. The data
 * starts immediately after it.
 */
struct bperf_sbuffer_node {
	size_t           start; /* Start index of unread data in this node */
	size_t           size;  /* Amount of data stored in this node */
	struct list_head list;  /* Linked list node */
	/* Data follows immediately after this */
};

#define BPERF_SBUFFER_MAX_SZ (BPERF_BLK_SZ - sizeof(struct bperf_sbuffer_node))

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
	struct bperf_sbuffer_node *ret = kmalloc(BPERF_BLK_SZ, GFP_KERNEL);
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
struct bperf_sbuffer {
	struct list_head list; /* Head node to linked list of buffers */
};

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
	return 0;
}

/**
 * @brief Free memory for buffer
 */
static void bperf_sbuffer_fini(struct bperf_sbuffer *sbuffer)
{
	struct list_head *next, *node = sbuffer->list.next;
	while (node != &sbuffer->list) {
		next = node->next;
		bperf_sbuffer_node_free(container_of(node, struct bperf_sbuffer_node, list));
		node = next;
	}
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

	while (true) {
		last_node = container_of(sbuffer->list.prev, struct bperf_sbuffer_node, list);
		space_left = BPERF_SBUFFER_MAX_SZ - last_node->size;
		amt_to_write = MIN(len - ret, space_left);

		if (amt_to_write > 0) {
			memcpy(bperf_sbuffer_node_data(last_node) + last_node->size, src + ret, amt_to_write);
			ret += amt_to_write;
			last_node->size += amt_to_write;
		}
		if (ret == len) {
			return ret;
		}

		if (!(new_node = bperf_sbuffer_node_new())) {
			return -ENOMEM;
		}
		list_add_tail(&new_node->list, &sbuffer->list);
	}
}

/**
 * @brief Read upto len bytes of data from the buffer into the destination (user-space)
 */
static ssize_t bperf_sbuffer_read(struct bperf_sbuffer *sbuffer, char __user *dest, size_t len)
{
	ssize_t amt_data_in_node, amt_to_write, ret = 0;
	struct list_head *ll_node = sbuffer->list.next;
	struct bperf_sbuffer_node *node;

	if (len == 0) {
		return 0;
	}

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
			amt_to_write -= copy_to_user(dest + ret, bperf_sbuffer_node_data(node) + node->start, amt_to_write);
			if (amt_to_write == 0) {
				break;
			}
			node->start += amt_to_write;
			ret += amt_to_write;
		}
		if (ret == len) {
			return ret;
		}
	}

	return ret;
}

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
	size_t               open_count;  /* Current open count for device file */
	struct bperf_sbuffer sbuffer;     /* Buffer of string data */
	struct task_struct   *thread_ptr; /* Pointer to task struct for kernel thread */
	/* Performance monitoring capabilities */
	uint32_t arch_perf_ver; /* Version ID of architectural performance monitoring */
	uint32_t num_ctr;       /* Number of general purpose counters per logical processor */
	uint32_t ctr_width;     /* Bit width of general purpose counters */
	uint32_t num_fix_ctr;   /* Number of fixed function counters */
	uint32_t fix_ctr_width; /* Bit width of fixed function counters */
	/* Whether specific events are available */
	bool     ev_core_cycle;        /* Core cycle event available */
	bool     ev_inst_retired;      /* Instruction retired event available */
	bool     ev_ref_cycles;        /* Reference cycles event available */
	bool     ev_llc_ref;           /* LLC reference event available */
	bool     ev_llc_miss;          /* LLC miss event available */
	bool     ev_branch_retired;    /* Branch instruction retired event available */
	bool     ev_branch_mispredict; /* Branch mispredict retired event available */
} STATE = { 0 };

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
	ssize_t ret = bperf_sbuffer_read(&state->sbuffer, buffer, size);
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
static int bperf_thread_function(void *unused)
{
	// Set up perf monitoring
	uint64_t perfevtsel_bak[1];
	uint64_t perfevtsel_cur[1];
	uint64_t pmc_last[1];
	uint64_t pmc_cur[1];

	// Get current state of perfevtsel MSR. If counting was enabled, disable it first
	perfevtsel_bak[0] = bperf_rdmsr(MSR_IA32_PERFEVTSEL(0));
	if (PERFEVTSEL_ENABLED(perfevtsel_bak[0])) {
		bperf_wrmsr(MSR_IA32_PERFEVTSEL(0), perfevtsel_bak[0] & ~PERFEVTSEL_FLAG_ENABLE);
	}
	pmc_last[0] = bperf_rdmsr(MSR_IA32_PMC(0));

	printk(KERN_INFO "bperf: Core: %u, original perfevtsel0: %#llx, cur pmc0: %#llx\n",
			smp_processor_id(), perfevtsel_bak[0], pmc_last[0]);

	perfevtsel_cur[0] = perfevtsel_bak[0] & PERFEVTSEL_RESERVED;
	perfevtsel_cur[0] |= PERFEVTSEL_FLAGS_SANE | PERFEVTSEL_CORE_CYCLES;
	bperf_wrmsr(MSR_IA32_PERFEVTSEL(0), perfevtsel_cur[0]);

	while (!kthread_should_stop()) {
		msleep(1000);
		printk(KERN_INFO "bperf: Thread function: %u\n", smp_processor_id());
		pmc_cur[0] = bperf_rdmsr(MSR_IA32_PMC(0));
		if (pmc_cur[0] >= pmc_last[0]) {
			printk(KERN_INFO "bperf: core cycles: %llu", pmc_cur[0] - pmc_last[0]);
		} else {
			printk(KERN_INFO "bperf: overflow\n");
		}
		pmc_last[0] = pmc_cur[0];
	}

	// Restore performance monitor settings
	bperf_wrmsr(MSR_IA32_PERFEVTSEL(0), perfevtsel_bak[0]);

	return 0;
}

/**
 * @brief The kernel module initialization function
 */
static int __init bperf_init(void)
{
	int ret;

	printk(KERN_INFO "bperf: Loading...\n");
	bperf_identify_processor();
	bperf_get_arch_perfmon_capabilities();
	if (STATE.arch_perf_ver <= 1) {
		printk(KERN_ALERT "bperf: Not enough support for performance monitoring\n");
		return -1;
	}

	printk(KERN_INFO "bperf: Num online CPUs: %u\n", num_online_cpus());

	// Allocate memory for string buffer
	if ((ret = bperf_sbuffer_init(&STATE.sbuffer)) < 0) {
		printk(KERN_ALERT "bperf: Failed to allocate string buffer\n");
		return ret;
	}

	// Try to dynamically allocate a major number for the device
	if ((ret = alloc_chrdev_region(&STATE.dev, 0, BPERF_DEV_COUNT, BPERF_NAME)) < 0) {
		printk(KERN_ALERT "bperf: Could not allocate major number\n");
		return ret;
	}
	printk(KERN_INFO "bperf: device = %d,%d\n", MAJOR(STATE.dev), MINOR(STATE.dev));

	// Create class struct
	if (IS_ERR(STATE.class = class_create(THIS_MODULE, BPERF_NAME))) {
		printk(KERN_ALERT "bperf: Failed to register device class\n");
		ret = PTR_ERR(STATE.class);
		goto error_class;
	}

	// Create device
	if (IS_ERR(STATE.device = device_create(STATE.class, NULL, STATE.dev, NULL, "bperf"))) {
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

	// Spawn kernel thread
	if (IS_ERR(STATE.thread_ptr = kthread_create(bperf_thread_function, NULL, "bperf_thread"))) {
		printk(KERN_ALERT "bperf: Failed to spawn worker thread\n");
		ret = PTR_ERR(STATE.thread_ptr);
		goto error_thread;
	}
	kthread_bind(STATE.thread_ptr, 1);
	wake_up_process(STATE.thread_ptr);

	// Success
	printk(KERN_INFO "bperf: Loaded!\n");
	return 0;

error_thread:
	cdev_del(&STATE.cdev);
error_cdev:
	device_destroy(STATE.class, STATE.dev);
error_device:
	class_destroy(STATE.class);
error_class:
	unregister_chrdev_region(STATE.dev, BPERF_DEV_COUNT);
	return ret;
}

/**
 * @brief The kernel module cleanup function
 */
static void __exit bperf_exit(void)
{
	printk(KERN_INFO "bperf: Unloading...\n");

	kthread_stop(STATE.thread_ptr);
	cdev_del(&STATE.cdev);
	device_destroy(STATE.class, STATE.dev);
	class_destroy(STATE.class);
	unregister_chrdev_region(STATE.dev, BPERF_DEV_COUNT);
	bperf_sbuffer_fini(&STATE.sbuffer);

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
