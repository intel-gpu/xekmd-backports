#ifndef __BACKPORT_LINUX_BITS_H
#define __BACKPORT_LINUX_BITS_H
#include <linux/version.h>
#include <linux/compiler.h>

#if LINUX_VERSION_IS_GEQ(4,19,0) || \
    LINUX_VERSION_IN_RANGE(4,14,119, 4,15,0)
#include_next <linux/bits.h>
#else
#include <linux/bitops.h>
#endif /* >= 4.19 */

#ifdef BPM_GENMASK_U32_NOT_PRESENT
/*
 * Generate a mask for the specified type @t. Additional checks are made to
 * guarantee the value returned fits in that type, relying on
 * -Wshift-count-overflow compiler check to detect incompatible arguments.
 * For example, all these create build errors or warnings:
 *
 * - GENMASK(15, 20): wrong argument order
 * - GENMASK(72, 15): doesn't fit unsigned long
 * - GENMASK_U32(33, 15): doesn't fit in a u32
 */
#define GENMASK_TYPE(t, h, l)					\
	((t)(GENMASK_INPUT_CHECK(h, l) +			\
	     (type_max(t) << (l) &				\
	      type_max(t) >> (BITS_PER_TYPE(t) - 1 - (h)))))

#define GENMASK_U32(h, l)	GENMASK_TYPE(u32, h, l)
#define GENMASK_U64(h, l)	GENMASK_TYPE(u64, h, l)

#define const_true(x) __builtin_choose_expr(__is_constexpr(x), x, false)

/*
 * Fixed-type variants of BIT(), with additional checks like GENMASK_TYPE(). The
 * following examples generate compiler warnings due to -Wshift-count-overflow:
 *
 * - BIT_U8(8)
 * - BIT_U32(-1)
 * - BIT_U32(40)
 */
#define BIT_INPUT_CHECK(type, nr) \
	BUILD_BUG_ON_ZERO(const_true((nr) >= BITS_PER_TYPE(type)))
#define BIT_TYPE(type, nr) ((type)(BIT_INPUT_CHECK(type, nr) + BIT_ULL(nr)))
#define BIT_U32(nr)	BIT_TYPE(u32, nr)

#endif

#endif /* __BACKPORT_LINUX_BITS_H */
