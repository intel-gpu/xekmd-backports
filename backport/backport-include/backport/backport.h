#ifndef __BACKPORT_H
#define __BACKPORT_H
#include <generated/autoconf.h>
#ifndef CONFIG_BACKPORT_INTEGRATE
#include <backport/autoconf.h>
#endif
#include <linux/kconfig.h>
#include <backport/backport_auto.h>

#ifndef __ASSEMBLY__
#define LINUX_BACKPORT(__sym) backport_ ##__sym
#endif

/* FIXME: Auto tools conversion is required for assign_str */
#if LINUX_VERSION_IS_LESS(6,10,0)
#define BPM_ASSIGN_STR_SECOND_ARG_PRESENT
#endif

#endif /* __BACKPORT_H */
