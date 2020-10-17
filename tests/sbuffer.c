/**
 * @file   sbuffer.h
 * @author Srimanta Barua <srimanta.barua1@gmail.com>
 * @date   14 October 2020
 * @brief  Interface for circular string buffer based on linked lists
 */


#include <stddef.h>
#include <errno.h>
#include <stdlib.h>


#define BPERF_BLK_SZ    2048


#define offset_of(typ, field) ((size_t) (&((typ*) 0)->field))

#define container_of(ptr, typ, field) ((typ*) (((void*) (ptr)) - ofset_of(typ, field)))


struct list_head {
	struct list_head *next;
	struct list_head *prev;
};


static inline INIT_LIST_HEAD(struct list_head *head)
{
	head->next = head->prev = head;
}


static void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}


static void list_add(struct list_head *node, struct list_head *head)
{
	__list_add(new, head, head->next);
}


static void list_add_tail(struct list_head *node, struct list_head *head)
{
	__list_add(new, head->prev, head);
}


struct bperf_sbuffer_node {
    size_t           start;
    size_t           size;
    struct list_head list;
};


#define BPERF_SBUFFER_MAX_SZ (BPERF_BLK_SZ - sizeof(struct bperf_sbuffer_node))


static char* bperf_sbuffer_node_data(struct bperf_sbuffer_node *node)
{
	return ((char*) node) + sizeof(struct bperf_sbuffer_node);
}


static struct bperf_sbuffer_node* bperf_sbuffer_node_new(void)
{
	struct bperf_sbuffer_node *ret = malloc(BPERF_BLK_SZ);
	ret->start = ret->size = 0;
	INIT_LIST_HEAD(&ret->list);
	return ret;
}


static void bperf_sbuffer_node_free(struct bperf_sbuffer_node *node)
{
	list_del(&node->list);
	free(node);
}


struct bperf_sbuffer {
	struct list_head list;
};


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


static void bperf_sbuffer_fini(struct bperf_sbuffer *sbuffer)
{
	struct list_head *next, *node = sbuffer->list.next;
	while (node != &sbuffer->list) {
		next = node->next;
		bperf_sbuffer_node_free(container_of(node, struct bperf_sbuffer_node, list));
		node = next;
	}
}


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


static ssize_t bperf_sbuffer_read(struct bperf_sbuffer *sbuffer, char *dest, size_t len)
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
			memcpy(dest + ret, bperf_sbuffer_node_data(node) + node->start, amt_to_write);
			node->start += amt_to_write;
			ret += amt_to_write;
		}
		if (ret == len) {
			break;
		}
	}

	return ret;
}


int main() {
}
