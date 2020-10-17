/**
 * @file    bperf.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    27 September 2020
 * @version 0.1
 * @brief A kernel module for high frequency counter sampling on x86_64 systems
 */

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

#define BPERF_NAME      "bperf"
#define BPERF_LICENSE   "GPL"
#define BPERF_AUTHOR    "Srimanta Barua <srimanta.barua1@gmail.com>"
#define BPERF_DESC      "Kernel module for high frequency counter sampling on x86_64 systems"
#define BPERF_VERSION   "0.1"
#define BPERF_DEV_COUNT 1
#define BPERF_BLK_SZ    64

#define MIN(x, y) ((x) < (y) ? (x) : (y))

MODULE_LICENSE(BPERF_LICENSE);
MODULE_AUTHOR(BPERF_AUTHOR);
MODULE_DESCRIPTION(BPERF_DESC);
MODULE_VERSION(BPERF_VERSION);

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
	if (!ret) {
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
	dev_t                dev;         /* Stores the device number */
	struct class         *class;      /* The device-driver class struct */
	struct device        *device;     /* The device-driver device struct */
	struct cdev          cdev;        /* Char device structure */
	size_t               open_count;  /* Current open count for device file */
	struct bperf_sbuffer sbuffer;     /* Buffer of string data */
	struct task_struct   *thread_ptr; /* Pointer to task struct for kernel thread */
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
 * @brief Thread function for polling counters
 */
static int bperf_thread_function(void *unused) {
	int i = 0;
	while (!kthread_should_stop()) {
		printk(KERN_INFO "bperf: Thread function: %d\n", i++);
		msleep(1000);
	}
	return 0;
}

/**
 * @brief The kernel module initialization function
 */
static int __init bperf_init(void)
{
	int ret;

	printk(KERN_INFO "bperf: Loading...\n");

	// Allocate memory for string buffer
	if ((ret = bperf_sbuffer_init(&STATE.sbuffer)) < 0) {
		printk(KERN_ALERT "bperf: Failed to allocate string buffer\n");
		return ret;
	}
	bperf_sbuffer_write(&STATE.sbuffer, "aaaaaaaa", 8);
	bperf_sbuffer_write(&STATE.sbuffer, "bbbbbbbb", 8);
	bperf_sbuffer_write(&STATE.sbuffer, "cccccccc", 8);
	bperf_sbuffer_write(&STATE.sbuffer, "dddddddd", 8);
	bperf_sbuffer_write(&STATE.sbuffer, "aaaaaaaa", 8);
	bperf_sbuffer_write(&STATE.sbuffer, "bbbbbbbb", 8);
	bperf_sbuffer_write(&STATE.sbuffer, "cccccccc", 8);
	bperf_sbuffer_write(&STATE.sbuffer, "dddddddd", 8);
	bperf_sbuffer_write(&STATE.sbuffer, "\n\0", 2);

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
	if (!(STATE.thread_ptr = kthread_run(bperf_thread_function, NULL, "bperf_thread"))) {
		printk(KERN_ALERT "bperf: Failed to spawn worker thread\n");
		ret = PTR_ERR(STATE.thread_ptr);
		goto error_thread;
	}

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
