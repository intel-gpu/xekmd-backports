/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_FAULT_INJECT_H
#define _BACKPORT_LINUX_FAULT_INJECT_H

#ifdef CONFIG_FAULT_INJECTION
#include_next <linux/fault-inject.h>
#else

#include <linux/types.h>
#include <linux/err.h>

struct fault_attr {
};

#define DECLARE_FAULT_ATTR(name) struct fault_attr name = {}

static inline int setup_fault_attr(struct fault_attr *attr, char *str)
{
       return 0; /* Note: 0 means error for __setup() handlers! */
}
static inline bool should_fail_ex(struct fault_attr *attr, ssize_t size, int flags)
{
       return false;
}
static inline bool should_fail(struct fault_attr *attr, ssize_t size)
{
       return false;
}

#ifndef CONFIG_FAULT_INJECTION_DEBUG_FS
static inline struct dentry *fault_create_debugfs_attr(const char *name,
                        struct dentry *parent, struct fault_attr *attr)
{
        return ERR_PTR(-ENODEV);
}
#endif /* CONFIG_FAULT_INJECTION_DEBUG_FS */
#endif /* CONFIG_FAULT_INJECTION */

#endif /* _BACKPORT_LINUX_FAULT_INJECT_H */
