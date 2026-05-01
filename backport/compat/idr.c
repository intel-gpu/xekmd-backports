// SPDX-License-Identifier: GPL-2.0-only
#include <linux/idr.h>

#ifdef BPM_IDA_FIND_FIRST_IDA_EXISTS_NOT_PRESENT
/**
 * ida_find_first_range - Get the lowest used ID.
 * @ida: IDA handle.
 * @min: Lowest ID to get.
 * @max: Highest ID to get.
 *
 * Get the lowest used ID between @min and @max, inclusive.  The returned
 * ID will not exceed %INT_MAX, even if @max is larger.
 *
 * Context: Any context. Takes and releases the xa_lock.
 * Return: The lowest used ID, or errno if no used ID is found.
 */
int ida_find_first_range(struct ida *ida, unsigned int min, unsigned int max)
{
	unsigned long index = min / IDA_BITMAP_BITS;
	unsigned int offset = min % IDA_BITMAP_BITS;
	unsigned long *addr, size, bit;
	unsigned long tmp = 0;
	unsigned long flags;
	void *entry;
	int ret;

	if ((int)min < 0)
		return -EINVAL;
	if ((int)max < 0)
		max = INT_MAX;

	xa_lock_irqsave(&ida->xa, flags);

	entry = xa_find(&ida->xa, &index, max / IDA_BITMAP_BITS, XA_PRESENT);
	if (!entry) {
		ret = -ENOENT;
		goto err_unlock;
	}

	if (index > min / IDA_BITMAP_BITS)
		offset = 0;
	if (index * IDA_BITMAP_BITS + offset > max) {
		ret = -ENOENT;
		goto err_unlock;
	}

	if (xa_is_value(entry)) {
		tmp = xa_to_value(entry);
		addr = &tmp;
		size = BITS_PER_XA_VALUE;
	} else {
		addr = ((struct ida_bitmap *)entry)->bitmap;
		size = IDA_BITMAP_BITS;
	}

	bit = find_next_bit(addr, size, offset);

	xa_unlock_irqrestore(&ida->xa, flags);

	if (bit == size ||
	    index * IDA_BITMAP_BITS + bit > max)
		return -ENOENT;

	return index * IDA_BITMAP_BITS + bit;

err_unlock:
	xa_unlock_irqrestore(&ida->xa, flags);
	return ret;
}
EXPORT_SYMBOL(ida_find_first_range);
#endif
