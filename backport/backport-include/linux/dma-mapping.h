#ifndef __BACKPORT_LINUX_DMA_MAPPING_H
#define __BACKPORT_LINUX_DMA_MAPPING_H
#include_next <linux/dma-mapping.h>

#ifndef DMA_MAPPING_ERROR
/*
 * A dma_addr_t can hold any valid DMA or bus address for the platform.  It can
 * be given to a device to use as a DMA source or target.  It is specific to a
 * given device and there may be a translation between the CPU physical address
 * space and the bus address space.
 *
 * DMA_MAPPING_ERROR is the magic error code if a mapping failed.  It should not
 * be used directly in drivers, but checked for using dma_mapping_error()
 * instead.
 */
#define DMA_MAPPING_ERROR		(~(dma_addr_t)0)
#endif /* DMA_MAPPING_ERROR */

#ifdef BPM_DMA_IOVA_STATE_NOT_PRESENT

struct dma_iova_state {
	dma_addr_t addr;
	u64 __size;
};

#define DMA_IOVA_USE_SWIOTLB    (1ULL << 63)

static inline bool dma_use_iova(struct dma_iova_state *state)
{
        return false;
}

static inline bool dma_iova_try_alloc(struct device *dev,
                                      struct dma_iova_state *state,
                                      phys_addr_t phys, size_t size)
{
        return false;
}

static inline void dma_iova_free(struct device *dev,
                                 struct dma_iova_state *state)
{
}

static inline void dma_iova_destroy(struct device *dev,
                                    struct dma_iova_state *state,
                                    size_t mapped_len, enum dma_data_direction dir,
                                    unsigned long attrs)
{
}

static inline int dma_iova_sync(struct device *dev,
                                struct dma_iova_state *state,
                                size_t offset, size_t size)
{
        return -EOPNOTSUPP;
}

static inline int dma_iova_link(struct device *dev,
                                struct dma_iova_state *state, phys_addr_t phys,
                                size_t offset, size_t size,
                                enum dma_data_direction dir, unsigned long attrs)
{
        return -EOPNOTSUPP;
}

static inline void dma_iova_unlink(struct device *dev,
                                   struct dma_iova_state *state, size_t offset,
                                   size_t size, enum dma_data_direction dir,
                                   unsigned long attrs)
{
}
#endif

#endif /* __BACKPORT_LINUX_DMA_MAPPING_H */
