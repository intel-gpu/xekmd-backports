#ifndef __BACKPORT_LINUX_ARGS_H
#define __BACKPORT_LINUX_ARGS_H

#ifdef HAVE_LINUX_ARGS_H
#include_next <linux/args.h>
#else
#include_next <linux/kernel.h>
#endif

#ifdef BPM_COUNT_ARGS_15_NOT_PRESENT
#undef COUNT_ARGS
#undef __COUNT_ARGS
#define __COUNT_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, \
		     _12, _13, _14, _15, _n, X...) _n
#define COUNT_ARGS(X...) \
	__COUNT_ARGS(, ##X, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, \
		     3, 2, 1, 0)
#endif

#endif
