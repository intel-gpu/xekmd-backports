/*
 * Copyright (C) 2024 Intel Corp.
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
 */
#ifndef _BPM_DEVCOREDUMP_H
#define _BPM_DEVCOREDUMP_H

#include_next <linux/devcoredump.h>

#ifdef BPM_COREDUMPM_TIMEOUT_NOT_PRESENT
#define dev_coredumpm_timeout(a,b,c,d,e,f,g,h) dev_coredumpm(a,b,c,d,e,f,g)
#endif

#ifdef BPM_DEVCOREDUMP_PUT_NOT_PRESENT
static inline void dev_coredump_put(struct device *dev){}
#endif

#endif /* _BPM_DEVCOREDUMP_H  */
