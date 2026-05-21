/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_IRQDESC_H__
#define __BACKPORT_LINUX_IRQDESC_H__

#include_next <linux/irqdesc.h>

#ifdef BPM_GENERIC_HANDLE_IRQ_SAFE_NOT_PRESENT
#define generic_handle_irq_safe(irq) generic_handle_irq((irq))
#endif

#endif /* __BACKPORT_LINUX_IRQDESC_H__ */
