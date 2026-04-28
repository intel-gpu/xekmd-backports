/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __BACKPORT_LINUX_LLIST_H
#define __BACKPORT_LINUX_LLIST_H

#include_next <linux/llist.h>

#ifdef BPM_INIT_LLIST_NODE_NOT_PRESENT
static inline void init_llist_node(struct llist_node *node)
{
	WRITE_ONCE(node->next, node);
}
#endif /* BPM_INIT_LLIST_NODE_NOT_PRESENT */

#endif /* __BACKPORT_LINUX_LLIST_H */
