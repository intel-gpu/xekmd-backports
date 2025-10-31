/*
 * Copyright (C) 2016 Red Hat
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 * Rob Clark <robdclark@gmail.com>
 */
#ifndef _BACKPORT_DRM_PRINT_H_
#define _BACKPORT_DRM_PRINT_H_

#include <drm/drm_device.h>
#include_next <drm/drm_print.h>

#ifdef BPM_DRM_DBG_PRINTER_NOT_PRESENT
#undef drm_dbg_printer
static inline struct drm_printer drm_dbg_printer(struct drm_device *drm,
                                                 enum drm_debug_category category,
                                                 const char *prefix)
{
        return drm_debug_printer(prefix);
}
#endif

#ifdef BPM_DRM_LINE_PRINTER_NOT_PRESENT
struct __drm_line_printer_ctx {
        struct drm_printer *parent;
        const char *prefix;
        unsigned int series;
        unsigned int counter;
};

static inline void __drm_printfn_line(struct drm_printer *p, struct va_format *vaf)
{
        struct __drm_line_printer_ctx *ctx = p->arg;
        unsigned int counter = ++ctx->counter;
        const char *prefix = ctx->prefix ?: "";
        const char *pad = ctx->prefix ? " " : "";

	if (ctx->series)
                drm_printf(ctx->parent, "%s%s%u.%u: %pV",
                          prefix, pad, ctx->series, counter, vaf);
        else
                drm_printf(ctx->parent, "%s%s%u: %pV", prefix, pad, counter, vaf);
}

static inline struct drm_printer drm_line_printer(struct drm_printer *p,
                                                  const char *prefix,
                                                  unsigned int series)
{
        static struct __drm_line_printer_ctx ctx;
        struct drm_printer lp;

	ctx.parent = p;
	ctx.prefix = prefix;
	ctx.series = series;
	ctx.counter = 0;

	lp.printfn = __drm_printfn_line;
	lp.arg = &ctx;

	return lp;
}
#endif

#ifdef BPM_DRM_DBG_RATELIMITED_NOT_PRESENT
#define drm_dbg_ratelimited(drm, fmt, ...) \
        __DRM_DEFINE_DBG_RATELIMITED(DRIVER, drm, fmt, ## __VA_ARGS__)
#endif

#ifdef BPM_DRM_COREDUMP_PRINTER_IS_FULL_NOT_PRESENT 
/**
 * drm_coredump_printer_is_full() - DRM coredump printer output is full
 * @p: DRM coredump printer
 *
 * DRM printer output is full, useful to short circuit coredump printing once
 * printer is full.
 *
 * RETURNS:
 * True if DRM coredump printer output buffer is full, False otherwise
 */
static inline bool drm_coredump_printer_is_full(struct drm_printer *p)
{
	struct drm_print_iterator *iterator = p->arg;

	if (p->printfn != __drm_printfn_coredump)
		return true;

	return !iterator->remain;
}
#endif

#endif /* _BACKPORT_DRM_PRINT_H_ */
