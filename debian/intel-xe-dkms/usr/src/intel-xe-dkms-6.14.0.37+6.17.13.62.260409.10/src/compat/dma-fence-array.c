// SPDX-License-Identifier: GPL-2.0-only

#include <linux/export.h>
#include <linux/slab.h>
#include <linux/dma-fence-array.h>

#ifdef BPM_DMA_FENCE_ARRAY_ALLOC_NOT_PRESENT
#define PENDING_ERROR 1
struct dma_fence_array *dma_fence_array_create(int num_fences,
                                               struct dma_fence **fences,
                                               u64 context, unsigned seqno,
                                               bool signal_on_any)
{
        struct dma_fence_array *array;

        array = dma_fence_array_alloc(num_fences);
        if (!array)
                return NULL;

        dma_fence_array_init(array, num_fences, fences,
                             context, seqno, signal_on_any);

        return array;
}
EXPORT_SYMBOL(dma_fence_array_create);

static void dma_fence_array_clear_pending_error(struct dma_fence_array *array)
{
	/* Clear the error flag if not actually set. */
	cmpxchg(&array->base.error, PENDING_ERROR, 0);
}

static void irq_dma_fence_array_work(struct irq_work *wrk)
{
        struct dma_fence_array *array = container_of(wrk, typeof(*array), work);

        dma_fence_array_clear_pending_error(array);

        dma_fence_signal(&array->base);
        dma_fence_put(&array->base);
}
void dma_fence_array_init(struct dma_fence_array *array,
                          int num_fences, struct dma_fence **fences,
                          u64 context, unsigned seqno,
                          bool signal_on_any)
{
        WARN_ON(!num_fences || !fences);

        array->num_fences = num_fences;

        spin_lock_init(&array->lock);
        dma_fence_init(&array->base, &dma_fence_array_ops, &array->lock,
                       context, seqno);
        init_irq_work(&array->work, irq_dma_fence_array_work);

        atomic_set(&array->num_pending, signal_on_any ? 1 : num_fences);
        array->fences = fences;

        array->base.error = PENDING_ERROR;

        /*
         * dma_fence_array objects should never contain any other fence
         * containers or otherwise we run into recursion and potential kernel
         * stack overflow on operations on the dma_fence_array.
         *
         * The correct way of handling this is to flatten out the array by the
         * caller instead.
         *
         * Enforce this here by checking that we don't create a dma_fence_array
         * with any container inside.
         */
        while (num_fences--)
                WARN_ON(dma_fence_is_container(fences[num_fences]));
}
EXPORT_SYMBOL(dma_fence_array_init);

struct dma_fence_array *dma_fence_array_alloc(int num_fences)
{
        struct dma_fence_array *array;
	size_t size = sizeof(*array);

	size += num_fences * sizeof(struct dma_fence_array_cb);
	array = kzalloc(size, GFP_KERNEL);

	return array;
}
EXPORT_SYMBOL(dma_fence_array_alloc);
#endif
