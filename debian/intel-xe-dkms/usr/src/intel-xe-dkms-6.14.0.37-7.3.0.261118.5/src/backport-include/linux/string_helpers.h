/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_STRING_HELPERS_H
#define __BACKPORT_LINUX_STRING_HELPERS_H

#include <linux/string.h>

#include_next <linux/string_helpers.h>

#ifdef BPM_PARSE_INT_ARRAY_USER_NOT_PRESENT
int parse_int_array_user(const char __user *from, size_t count, int **array);
extern char *get_options(const char *str, int nints, int *ints);
#endif

#endif /* __BACKPORT_LINUX_STRING_HELPERS_H */
