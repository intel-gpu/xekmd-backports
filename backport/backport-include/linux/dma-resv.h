#ifndef __BACKPORT_LINUX_DMA_RESV_H
#define __BACKPORT_LINUX_DMA_RESV_H

#include_next <linux/dma-resv.h>

#ifdef BPM_DMA_RESV_USAGE_NOT_PRESENT
enum dma_resv_usage {
	DMA_RESV_USAGE_KERNEL,
	DMA_RESV_USAGE_WRITE,
	DMA_RESV_USAGE_READ,
	DMA_RESV_USAGE_BOOKKEEP,
};

static inline enum dma_resv_usage dma_resv_usage_rw(bool write)
{
	return write ? DMA_RESV_USAGE_READ : DMA_RESV_USAGE_WRITE;
}
#endif
#endif
