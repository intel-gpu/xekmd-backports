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
#ifndef _BACKPORT_STRING_CHOICES_H
#define _BACKPORT_STRING_CHOICES_H

#if defined(HAVE_LINUX_STRING_CHOICES_H) && \
	!defined(BPM_STR_PLURAL_NOT_PRESENT)
#include_next <linux/string_choices.h>
#else

static inline const char *str_plural(size_t num)
{
	return num == 1 ? "" : "s";
}

static inline const char *str_up_down(bool v)
{
	return v ? "up" : "down";
}

static inline const char *str_yes_no(bool v)
{
	return v ? "yes" : "no";
}

static inline const char *str_on_off(bool v)
{
	return v ? "on" : "off";
}

static inline const char *str_enable_disable(bool v)
{
	return v ? "enable" : "disable";
}

static inline const char *str_enabled_disabled(bool v)
{
	return v ? "enabled" : "disabled";
}

#endif

#endif /* _BACKPORT_STRING_CHOICES_H */
