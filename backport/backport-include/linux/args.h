#ifndef __BACKPORT_LINUX_ARGS_H
#define __BACKPORT_LINUX_ARGS_H

#ifdef HAVE_LINUX_ARGS_H
#include_next <linux/args.h>
#else
#include_next <linux/kernel.h>
#endif
#endif
