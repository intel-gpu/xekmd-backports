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
#include <linux/module.h>

struct devcd_entry {
	struct device devcd_dev;
	void *data;
	size_t datalen;
	struct mutex mutex;
	bool delete_work;
	struct module *owner;
	ssize_t (*read)(char *buffer, loff_t offset, size_t count,
			void *data, size_t datalen);
	void (*free)(void *data);
	struct delayed_work del_wk;
	struct device *failing_dev;
};

static struct devcd_entry *dev_to_devcd(struct device *dev)
{
	return container_of(dev, struct devcd_entry, devcd_dev);
}


static int devcd_free(struct device *dev, void *data)
{
	struct devcd_entry *devcd = dev_to_devcd(dev);

	mutex_lock(&devcd->mutex);
	if (!devcd->delete_work)
		devcd->delete_work = true;

	flush_delayed_work(&devcd->del_wk);
	mutex_unlock(&devcd->mutex);
	return 0;
}

static inline void dev_coredump_put(struct device *dev)
{
	struct module *mod = NULL;
	mod = kmalloc(sizeof(*mod), GFP_KERNEL);
	
	/* Use dummy module to avoid new coredump creation in case if its not created at all */
	mod->state = MODULE_STATE_GOING;

	devcd_free(dev, NULL);
	
	/* This will call the devcoredump with exiting device in device class of devcodedump
	 * and attempts to put_device follwed by freeing of data(in our case its NULL)
	 * */
	dev_coredumpm(dev, mod, NULL, 0, GFP_KERNEL, NULL, NULL);
}
#endif

#endif /* _BPM_DEVCOREDUMP_H  */
