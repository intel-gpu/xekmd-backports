/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_BITMAP_H
#define _BACKPORT_LINUX_BITMAP_H
#include_next <linux/bitmap.h>

static inline unsigned int __backport_bitmap_weighted_or(unsigned long *dst,
		const unsigned long *src1,
		const unsigned long *src2,
		unsigned int nbits)
{
	bitmap_or(dst, src1, src2, nbits);
	return bitmap_weight(dst, nbits);
}

#undef bitmap_weighted_or
#define bitmap_weighted_or(dst, src1, src2, nbits) \
	__backport_bitmap_weighted_or((dst), (src1), (src2), (nbits))

#endif /* _BACKPORT_LINUX_BITMAP_H */

