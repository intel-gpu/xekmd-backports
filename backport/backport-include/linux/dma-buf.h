/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Header file for dma buffer sharing framework.
 *
 * Copyright(C) 2011 Linaro Limited. All rights reserved.
 * Author: Sumit Semwal <sumit.semwal@ti.com>
 *
 * Many thanks to linaro-mm-sig list, and specially
 * Arnd Bergmann <arnd@arndb.de>, Rob Clark <rob@ti.com> and
 * Daniel Vetter <daniel@ffwll.ch> for their support in creation and
 * refining of this idea.
 */
#ifndef __BACKPORT_DMA_BUF_H__
#define __BACKPORT_DMA_BUF_H__

#include_next <linux/dma-buf.h>
#include <linux/module.h>

#ifdef MODULE_IMPORT_NS
#ifdef BPM_MODULE_IMPORT_TO_STRING_LITERAL_PRESENT
MODULE_IMPORT_NS(DMA_BUF);
#else
MODULE_IMPORT_NS("DMA_BUF");
#endif
#endif

#endif /*__BACKPORT_DMA_BUF_H__*/
