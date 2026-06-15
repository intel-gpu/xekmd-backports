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

/*
 * range_overflows() - Check if a range overflows past a maximum
 * @start: Starting value
 * @size: Size of the range
 * @max: Maximum value (exclusive)
 *
 * Returns true if (start + size) would overflow past max.
 *
 * From kernel 6.6 onwards this lives in <drm/drm_buddy.h>, which is included
 * after this header, so a plain #ifndef guard cannot see it and we would clash
 * with a redefinition warning. Use the BPM_RANGE_OVERFLOWS_NOT_PRESENT probe
 * (feature detection at configure time) so the fallback is only provided when
 * the kernel does not supply range_overflows() at all.
 */
#ifdef BPM_RANGE_OVERFLOWS_NOT_PRESENT
#define range_overflows(start, size, max) ({   \
        typeof(start) __start = (start);        \
        typeof(size) __size = (size);           \
        typeof(max) __max = (max);              \
        (void)(&__start == &__size);            \
        (void)(&__start == &__max);             \
        __start > __max - __size;               \
})
#endif

/*
 * struct_size_t() - Calculate size of struct with trailing variable array
 * @TYPE: struct type name
 * @member: name of the array member
 * @count: number of elements in the array
 *
 * Like struct_size() but takes a type instead of a pointer.
 * Added in newer kernels for type-safe flexible array allocation.
 */
#ifndef struct_size_t
#define struct_size_t(TYPE, member, count)  \
        struct_size((TYPE *)NULL, member, count)
#endif

#endif /* __BACKPORT_LINUX_OVERFLOW_H */
