/*
 * Copyright © 2024 Intel Corporation
 */

#ifndef __BACKPORT_LIST_LRU_H__
#define __BACKPORT_LIST_LRU_H__

#include <linux/version.h>
#include_next <linux/list_lru.h>

/*
 * list_lru_add() gained nid/memcg parameters somewhere between v6.6 and v6.8
 * (and was also backported to Ubuntu 6.8 kernels). LINUX_VERSION_CODE cannot
 * reliably detect this because the change appeared at different base versions
 * across distributions.
 *
 * BPM_LIST_LRU_ADD_4ARGS_NOT_PRESENT is defined by the backport build system via a
 * compile-time probe when the 4-arg signature is detected. This correctly handles:
 *   6.6 LTS    – 2-arg list_lru_add → call with 2 args
 *   Ubuntu 6.8 – 4-arg list_lru_add → pass all 4 args through
 *   6.12 LTS   – 4-arg list_lru_add → pass all 4 args through
 *   7.0+       – 4-arg list_lru_add → pass all 4 args through
 */

#undef list_lru_add

#ifdef BPM_LIST_LRU_ADD_4ARGS_NOT_PRESENT
#ifdef BPM_LIST_LRU_ONE_LOCK_NOT_PRESENT
/*
 * New struct layout (ubuntu-7.0, redhat-10.1+): spinlock and atomic_long_t
 * nr_items moved into struct list_lru_one.  list_lru_add() is not exported;
 * inline the null-memcg path using public struct fields.
 */
static __always_inline bool
backport_list_lru_add(struct list_lru *lru, struct list_head *item,
			int nid, struct mem_cgroup *memcg)
{
	struct list_lru_one *l = &lru->node[nid].lru;
	bool ret = false;

	spin_lock(&l->lock);
	if (list_empty(item)) {
		list_add_tail(item, &l->list);
		l->nr_items++;
		atomic_long_inc(&lru->node[nid].nr_items);
		ret = true;
	}
	spin_unlock(&l->lock);
	return ret;
}
#else
/*
 * Old struct layout (6.8–6.12 LTS, ubuntu-6.8, backporting headers): spinlock
 * is in struct list_lru_node, nr_items is long.  list_lru_add() may not be
 * exported; inline the null-memcg path using public struct fields.
 */
static __always_inline bool
backport_list_lru_add(struct list_lru *lru, struct list_head *item,
			int nid, struct mem_cgroup *memcg)
{
	struct list_lru_node *nlru = &lru->node[nid];
	bool ret = false;

	spin_lock(&nlru->lock);
	if (list_empty(item)) {
		list_add_tail(item, &nlru->lru.list);
		nlru->lru.nr_items++;
		nlru->nr_items++;
		ret = true;
	}
	spin_unlock(&nlru->lock);
	return ret;
}
#endif /* BPM_LIST_LRU_ONE_LOCK_NOT_PRESENT */
#else
/*
 * 6.6 LTS: 2-arg list_lru_add, exported.
 */
static __always_inline bool
backport_list_lru_add(struct list_lru *lru, struct list_head *item,
			int nid, struct mem_cgroup *memcg)
{
	return list_lru_add(lru, item);
}
#endif /* BPM_LIST_LRU_ADD_4ARGS_NOT_PRESENT */

#define list_lru_add(lru, item, nid, memcg) \
	backport_list_lru_add((lru), (item), (nid), (memcg))

/*
 * list_lru_walk callback: the spinlock_t *lock parameter was dropped in v6.13.
 *
 * Old (pre-6.13) type: (item, list, lock, cb_arg)  – 4 args
 * New (6.13+)    type: (item, list, cb_arg)         – 3 args
 *
 * BPM_HAVE_LIST_LRU_WALK_CB_NOT_PRESENT is used for distro kernels (e.g.
 * Ubuntu 7.0) that may not report LINUX_VERSION_CODE >= 6.13 but have
 * already dropped the spinlock parameter.
 */
#if defined(BPM_HAVE_LIST_LRU_WALK_CB_NOT_PRESENT) || \
    LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
	/* New kernel: callback signature is (item, list, cb_arg) */
	#define LIST_LRU_WALK_CALLBACK(name) \
		static enum lru_status name(struct list_head *item, \
					    struct list_lru_one *list, \
					    void *cb_arg)
#else
	/* Old kernel: wrap 4-arg callback to call 3-arg impl */
	#define LIST_LRU_WALK_CALLBACK(name) \
		static enum lru_status name##_impl(struct list_head *item, \
						   struct list_lru_one *list, \
						   void *cb_arg); \
		static enum lru_status name(struct list_head *item, \
					    struct list_lru_one *list, \
					    spinlock_t *lock, \
					    void *cb_arg) { \
			return name##_impl(item, list, cb_arg); \
		} \
		static enum lru_status name##_impl(struct list_head *item, \
						   struct list_lru_one *list, \
						   void *cb_arg)
#endif

#endif /* __BACKPORT_LIST_LRU_H__ */
