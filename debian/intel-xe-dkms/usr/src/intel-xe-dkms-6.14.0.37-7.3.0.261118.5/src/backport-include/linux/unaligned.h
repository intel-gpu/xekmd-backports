#ifndef __BACKPORT_LINUX_UNALIGNED_H
#define __BACKPORT_LINUX_UNALIGNED_H

#include <backport/backport_auto.h>

#ifndef HAVE_LINUX_UNALIGNED_H
#include <asm/unaligned.h>
#else
#include_next <linux/unaligned.h>
#endif

#endif /* __BACKPORT_LINUX_UNALIGNED_H */
