/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_LIST_H__
#define __BACKPORT_LINUX_LIST_H__

#include_next <linux/list.h>

#ifdef BPM_LIST_COUNT_NODES_NOT_PRESENT
static inline size_t __bp_list_count_nodes(struct list_head *head)
{
        struct list_head *pos;
        size_t count = 0;

        list_for_each(pos, head)
                count++;

        return count;
}
#define list_count_nodes(head) __bp_list_count_nodes((head))
#endif

#endif /* __BACKPORT_LINUX_LIST_H__ */
