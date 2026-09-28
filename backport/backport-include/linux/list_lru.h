/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __BACKPORT_LIST_LRU_H__
#define __BACKPORT_LIST_LRU_H__

#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include_next <linux/list_lru.h>

#ifdef BPM_LIST_LRU_ADD_4ARGS_NOT_PRESENT
static inline bool
backport_list_lru_add(struct list_lru *lru, struct list_head *item, int nid,
		      struct mem_cgroup *memcg)
{
	struct list_lru_node *nlru = &lru->node[nid];

	spin_lock(&nlru->lock);
	if (list_empty(item)) {
		list_add_tail(item, &nlru->lru.list);
		nlru->lru.nr_items++;
		nlru->nr_items++;
		spin_unlock(&nlru->lock);
		return true;
	}
	spin_unlock(&nlru->lock);
	return false;
}
#define list_lru_add(lru, item, nid, memcg) \
	backport_list_lru_add(lru, item, nid, memcg)
#endif

#ifdef BPM_LIST_LRU_ADD_EXP_SYM_NOT_PRESENT
static inline bool
backport_list_lru_add(struct list_lru *lru, struct list_head *item, int nid,
		      struct mem_cgroup *memcg)
{
	struct list_lru_node *nlru = &lru->node[nid];
	struct list_lru_one *l = &nlru->lru;
	bool ret = false;

	spin_lock(&l->lock);
	if (list_empty(item)) {
		list_add_tail(item, &l->list);
		l->nr_items++;
		atomic_long_inc(&nlru->nr_items);
		ret = true;
	}
	spin_unlock(&l->lock);

	return ret;
}
#define list_lru_add(lru, item, nid, memcg) \
	backport_list_lru_add(lru, item, nid, memcg)
#endif

#endif /* __BACKPORT_LIST_LRU_H__ */
