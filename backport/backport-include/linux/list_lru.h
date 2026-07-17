/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __BACKPORT_LIST_LRU_H__
#define __BACKPORT_LIST_LRU_H__

#include <linux/version.h>
#include_next <linux/list_lru.h>

#ifdef BPM_LIST_LRU_ADD_4ARGS_NOT_PRESENT
#define list_lru_add(lru, item, nid, memcg) list_lru_add(lru, item)
#elif defined(BPM_LIST_LRU_ADD_OBJ_NOT_PRESENT)
#define list_lru_add(lru, item, nid, memcg) list_lru_add_obj(lru, item)
#endif

#endif /* __BACKPORT_LIST_LRU_H__ */
