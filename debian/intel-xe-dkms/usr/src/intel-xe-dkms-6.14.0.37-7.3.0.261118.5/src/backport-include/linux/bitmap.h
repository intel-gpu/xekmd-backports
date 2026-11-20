/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_BITMAP_H
#define _BACKPORT_LINUX_BITMAP_H
#include_next <linux/bitmap.h>

#ifdef BPM_UNDERSCORE_BITMAP_WEIGHTED_OR_NOT_PRESENT
unsigned int __bitmap_weighted_or(unsigned long *dst, const unsigned long *bitmap1,
				  const unsigned long *bitmap2, unsigned int nbits);
#endif /* BPM_UNDERSCORE_BITMAP_WEIGHTED_OR_NOT_PRESENT */

#ifdef BPM_BITMAP_WEIGHTED_OR_NOT_PRESENT
static __always_inline
unsigned int bitmap_weighted_or(unsigned long *dst, const unsigned long *src1,
				const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits)) {
		*dst = *src1 | *src2;
		return hweight_long(*dst & BITMAP_LAST_WORD_MASK(nbits));
	} else {
		return __bitmap_weighted_or(dst, src1, src2, nbits);
	}
}
#endif /* BPM_BITMAP_WEIGHTED_OR_NOT_PRESENTT */

#endif /* _BACKPORT_LINUX_BITMAP_H */
