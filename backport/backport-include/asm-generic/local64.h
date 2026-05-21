/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_ASM_GENERIC_LOCAL64_H
#define __BACKPORT_ASM_GENERIC_LOCAL64_H

#include_next <asm-generic/local64.h>

#ifdef BPM_LOCAL64_TRY_CMPXCHG_NOT_PRESENT
#define local64_try_cmpxchg(l, old, new)                                \
({                                                                      \
        u64 __old = *(old);                                             \
        u64 __ret = (u64)local64_cmpxchg((l), __old, (new));            \
        if (__ret != __old)                                             \
                *(old) = __ret;                                         \
        __ret == __old;                                                 \
})
#endif

#endif /* __BACKPORT_ASM_GENERIC_LOCAL64_H */
