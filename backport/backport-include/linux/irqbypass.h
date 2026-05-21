/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IRQ offload/bypass manager
 *
 * Copyright (C) 2015 Red Hat, Inc.
 * Copyright (c) 2015 Linaro Ltd.
 */
#ifndef _BACKPORT_IRQBYPASS_H
#define _BACKPORT_IRQBYPASS_H

#include_next <linux/irqbypass.h>
#include <linux/eventfd.h>

#ifdef BPM_IRQ_BYPASS_REGISTER_PRODUCER_ARG3_NOT_PRESENT
static inline int bpm_irq_bypass_register_producer(struct irq_bypass_producer *producer,
						struct eventfd_ctx *eventfd, int irq)
{
	return irq_bypass_register_producer(producer);
}
#define irq_bypass_register_producer bpm_irq_bypass_register_producer
#endif
#endif
