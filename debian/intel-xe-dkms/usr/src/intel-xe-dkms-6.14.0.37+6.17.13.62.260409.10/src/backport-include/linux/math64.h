/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_MATH64_H
#define __BACKPORT_MATH64_H

#include_next<linux/math64.h>

#ifdef BPM_DIV_U64_ROUND_UP_NOT_PRESENT
/**
 * DIV_U64_ROUND_UP - unsigned 64bit divide with 32bit divisor rounded up
 * @ll: unsigned 64bit dividend
 * @d: unsigned 32bit divisor
 *
 * Divide unsigned 64bit dividend by unsigned 32bit divisor
 * and round up.
 *
 * Return: dividend / divisor rounded up
 */
#define DIV_U64_ROUND_UP(ll, d)		\
	({ u32 _tmp = (d); div_u64((ll) + _tmp - 1, _tmp); })
#endif

#endif /* __BACKPORT_MATH64_H */
