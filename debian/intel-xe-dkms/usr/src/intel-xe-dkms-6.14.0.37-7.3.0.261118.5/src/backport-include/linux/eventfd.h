/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/linux/eventfd.h
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#ifndef _BACKPORT_EVENTFD_H
#define _BACKPORT_EVENTFD_H

#include_next <linux/eventfd.h>

#ifdef BPM_EVENTFD_SIGNAL_ARG1_NOT_PRESENT
static inline int bpm_eventfd_signal(struct eventfd_ctx *ctx)
{
	return eventfd_signal(ctx, 1);
}
#define eventfd_signal bpm_eventfd_signal
#endif
#endif
