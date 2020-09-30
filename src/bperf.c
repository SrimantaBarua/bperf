/**
 * @file    bperf.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    27 September 2020
 * @version 0.1
 * @brief A kernel module for high frequency counter sampling on x86_64 systems
 */

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#define BPERF_NAME    "bperf"
#define BPERF_LICENSE "GPL"
#define BPERF_AUTHOR  "Srimanta Barua <srimanta.barua1@gmail.com>"
#define BPERF_DESC    "Kernel module for high frequency counter sampling on x86_64 systems"
#define BPERF_VERSION "0.1"

#define BPERF_DEV_COUNT 1

MODULE_LICENSE(BPERF_LICENSE);
MODULE_AUTHOR(BPERF_AUTHOR);
MODULE_DESCRIPTION(BPERF_DESC);
MODULE_VERSION(BPERF_VERSION);

/**
 * @brief Global module state
 */
static struct global_state {
	dev_t         dev;     // Stores the device number
	struct class  *class;  // The device-driver class struct
	struct device *device; // The device-driver device struct
} STATE = {
	.dev = 0,
	.class = NULL,
	.device = NULL,
};

/**
 * @brief The kernel module initialization function
 */
static int __init bperf_init(void)
{
	int ret;

	printk(KERN_INFO "bperf: Loading...\n");

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
	if (IS_ERR(STATE.device = device_create(STATE.class, NULL, STATE.dev, NULL, "bperf%d", MINOR(STATE.dev)))) {
		printk(KERN_ALERT "bperf: Failed to create device file\n");
		ret = PTR_ERR(STATE.device);
		goto error_device;
	}

	goto success;

error_device:
	class_destroy(STATE.class);
error_class:
	unregister_chrdev_region(STATE.dev, BPERF_DEV_COUNT);
	return ret;

success:
	printk(KERN_INFO "bperf: Loaded!\n");
	return 0;
}

/**
 * @brief The kernel module cleanup function
 */
static void __exit bperf_exit(void)
{
	printk(KERN_INFO "bperf: Unloading...\n");

	device_destroy(STATE.class, STATE.dev);
	class_destroy(STATE.class);
	unregister_chrdev_region(STATE.dev, BPERF_DEV_COUNT);

	printk(KERN_INFO "bperf: Unloaded!\n");
}

/**
 * @brief Identify the initialization and cleanup functions
 */
module_init(bperf_init);
module_exit(bperf_exit);
