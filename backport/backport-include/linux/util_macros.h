#ifndef __BACKPORT_LINUX_UTIL_MACROS_H
#define __BACKPORT_LINUX_UTIL_MACROS_H

#include_next <linux/util_macros.h>
#ifndef for_each_if
#define for_each_if(condition) if (!(condition)) {} else
#endif

#endif /* __BACKPORT_LINUX_UTIL_MACROS_H */
