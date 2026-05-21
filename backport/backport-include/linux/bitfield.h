/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_BITFIELD_H__
#define __BACKPORT_LINUX_BITFIELD_H__

#include_next <linux/bitfield.h>

#ifdef BPM_FIELD_PREP_CONST_NOT_PRESENT
#define FIELD_PREP_CONST(_mask, _val)                                   \
        (                                                               \
                BUILD_BUG_ON_ZERO((_mask) == 0) +                       \
                BUILD_BUG_ON_ZERO(~((_mask) >> __bf_shf(_mask)) & (_val)) + \
                BUILD_BUG_ON_ZERO((((_mask) + (1ULL << __bf_shf(_mask))) & \
                                   (((_mask) + (1ULL << __bf_shf(_mask))) - 1)) != 0) + \
                (((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask))  \
        )
#endif

#endif /* __BACKPORT_LINUX_BITFIELD_H__ */
