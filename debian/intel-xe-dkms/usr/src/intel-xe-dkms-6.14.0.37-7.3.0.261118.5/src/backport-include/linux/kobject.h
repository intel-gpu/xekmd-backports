#ifndef __BACKPORT_LINUX_KOBJECT_H
#define __BACKPORT_LINUX_KOBJECT_H

#include_next <linux/kobject.h>

#define kobject_init(_kobj, _ktype) \
	kobject_init((_kobj), (struct kobj_type *)(_ktype))

#define kobject_init_and_add(_kobj, _ktype, _parent, _fmt, ...) \
	kobject_init_and_add((_kobj), (struct kobj_type *)(_ktype), \
			     (_parent), (_fmt), ##__VA_ARGS__)

#endif /* __BACKPORT_LINUX_KOBJECT_H */
