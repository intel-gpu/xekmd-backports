/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_MEI_AUX_H_
#define _BACKPORT_LINUX_MEI_AUX_H_

#ifdef HAVE_LINUX_MEI_AUX_H
#include_next <linux/mei_aux.h>
#else

#include <linux/auxiliary_bus.h>
#include <linux/ioport.h>

struct mei_aux_device {
        struct auxiliary_device aux_dev;
        int irq;
        struct resource bar;
        struct resource ext_op_mem;
        bool slow_firmware;
};

#define auxiliary_dev_to_mei_aux_dev(auxiliary_dev) \
        container_of(auxiliary_dev, struct mei_aux_device, aux_dev)

#endif
#endif /* _LINUX_MEI_AUX_H */
