/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_FIND_H__
#define __BACKPORT_LINUX_FIND_H__

#include <linux/bitops.h>
#include <linux/kernel.h>

#ifdef BPM_FOR_EACH_OR_BIT_NOT_PRESENT
static inline unsigned long find_next_or_bit(const unsigned long *addr1,
					     const unsigned long *addr2,
					     unsigned long size,
					     unsigned long offset)
{
	unsigned long n1 = find_next_bit(addr1, size, offset);
	unsigned long n2 = find_next_bit(addr2, size, offset);

	return min(n1, n2);
}

#define for_each_or_bit(bit, addr1, addr2, size) \
	for ((bit) = 0; \
	     (bit) = find_next_or_bit((addr1), (addr2), (size), (bit)), (bit) < (size); \
	     (bit)++)

#define for_each_set_bitrange(b, e, addr, size) \
	for ((b) = 0; \
	     (b) = find_next_bit((addr), (size), (b)), \
	     (e) = find_next_zero_bit((addr), (size), (b) + 1), \
	     (b) < (size); \
	     (b) = (e) + 1)

#define for_each_clear_bitrange(b, e, addr, size) \
	for ((b) = 0; \
	     (b) = find_next_zero_bit((addr), (size), (b)), \
	     (e) = find_next_bit((addr), (size), (b) + 1), \
	     (b) < (size); \
	     (b) = (e) + 1)
#endif
#endif /* __BACKPORT_LINUX_FIND_H__ */
