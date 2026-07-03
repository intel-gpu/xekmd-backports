/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_BITMAP_H
#define _BACKPORT_LINUX_BITMAP_H
#include_next <linux/bitmap.h>

#ifdef BPM_BITMAP_WEIGHTED_OR_NOT_PRESENT
/* bitmap_weighted_or - return the weight of the OR of two bitmaps
 * Similar to bitmap_or() but returns the weight (number of bits set)
 * instead of just performing the operation.
 * This function performs: dst = src1 | src2 and returns popcount(dst)
 */
static inline unsigned int bitmap_weighted_or(unsigned long *dst,
		const unsigned long *src1,
		const unsigned long *src2,
		unsigned int nbits)
{
	bitmap_or(dst, src1, src2, nbits);
	return bitmap_weight(dst, nbits);
}
#endif /* BPM_BITMAP_WEIGHTED_OR_NOT_PRESENT */

#endif /* _BACKPORT_LINUX_BITMAP_H */

