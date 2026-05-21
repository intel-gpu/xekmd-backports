/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_COMPILER_TYPES_H
#define __BACKPORT_LINUX_COMPILER_TYPES_H

#include_next <linux/compiler_types.h>

/* Ensure newer attribute shims (e.g. __counted_by) are always available. */
#include <linux/compiler_attributes.h>

#ifndef __diag_ignore_all
#define __diag_ignore_all(option, comment)
#endif

#endif /* __BACKPORT_LINUX_COMPILER_TYPES_H */
