/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_OVERFLOW_H
#define __BACKPORT_LINUX_OVERFLOW_H

#include_next <linux/overflow.h>

/*
 * overflows_type() was added in newer kernels.
 * Fallback: value overflows target type T if truncating cast changes it.
 */
#ifndef overflows_type
#define overflows_type(n, T) ({                                 \
        typeof(n) __n = (n);                                    \
        __n != (typeof(n))((T)(__n));                           \
})
#endif

#endif /* __BACKPORT_LINUX_OVERFLOW_H */
