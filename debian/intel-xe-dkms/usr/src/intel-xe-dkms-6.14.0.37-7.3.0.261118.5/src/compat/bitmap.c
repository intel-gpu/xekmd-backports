// SPDX-License-Identifier: GPL-2.0

#include <linux/bitmap.h>
#include <linux/export.h>

#ifdef BPM_UNDERSCORE_BITMAP_WEIGHTED_OR_NOT_PRESENT
#define BITMAP_WEIGHT(FETCH, bits)	\
({										\
	unsigned int __bits = (bits), idx, w = 0;				\
										\
	for (idx = 0; idx < __bits / BITS_PER_LONG; idx++)			\
		w += hweight_long(FETCH);					\
										\
	if (__bits % BITS_PER_LONG)						\
		w += hweight_long((FETCH) & BITMAP_LAST_WORD_MASK(__bits));	\
										\
	w;									\
})

unsigned int __bitmap_weighted_or(unsigned long *dst, const unsigned long *bitmap1,
				  const unsigned long *bitmap2, unsigned int bits)
{
	return BITMAP_WEIGHT(({dst[idx] = bitmap1[idx] | bitmap2[idx]; dst[idx]; }), bits);
}
EXPORT_SYMBOL(__bitmap_weighted_or);
#endif /* BPM_UNDERSCORE_BITMAP_WEIGHTED_OR_NOT_PRESENT */