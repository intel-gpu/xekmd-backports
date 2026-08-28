#ifndef __BACKPORT_LINUX_ARGS_H
#define __BACKPORT_LINUX_ARGS_H

#ifdef HAVE_LINUX_ARGS_H
#include_next <linux/args.h>
#else
#include_next <linux/kernel.h>
#endif

/*
 * COUNT_ARGS() has grown across kernel versions:
 *   - v5.15 and older <linux/kernel.h>: counts up to 12 arguments.
 *   - v6.6+           <linux/args.h>:   counts up to 15 arguments.
 *
 * The xe RTP macros feed COUNT_ARGS() into a token paste to pick
 * XE_RTP_PASTE_<N>, so a 12-arg-limited COUNT_ARGS() miscounts
 * anything larger and produces bogus identifiers like
 * XE_RTP_PASTE_GRAPHICS_VERSION, breaking xe_wa_oob.c rules that
 * pass more than 12 arguments to XE_RTP_RULES() (e.g. WA 14025515070).
 *
 * Force the upstream 15-argument definition regardless of what the
 * target kernel supplied, so multi-arg XE_RTP_RULES() (up to 15 args)
 * expands correctly on both old and new kernels.
 */
#undef COUNT_ARGS
#undef __COUNT_ARGS
#define __COUNT_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11,	\
		     _12, _13, _14, _15, _n, X...) _n
#define COUNT_ARGS(X...)						\
	__COUNT_ARGS(, ##X, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4,	\
		     3, 2, 1, 0)

#ifndef CONCATENATE
#define __CONCAT(a, b) a ## b
#define CONCATENATE(a, b) __CONCAT(a, b)
#endif

#endif
