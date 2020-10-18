/**
 * @file    sbuffer.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    17 October 2020
 * @version 0.1
 * @brief   Split off logic for string buffer. Is directly included, not compiled separately
 */

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
