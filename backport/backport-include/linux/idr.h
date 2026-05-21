/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/linux/idr.h
 * 
 * 2002-10-18  written by Jim Houston jim.houston@ccur.com
 *	Copyright (C) 2002 by Concurrent Computer Corporation
 *
 * Small id to pointer translation service avoiding fixed sized
 * tables.
 */

#ifndef _BACKPORT_IDR_H__
#define _BACKPORT_IDR_H__

#include_next <linux/idr.h>

#ifdef BPM_IDA_FIND_FIRST_IDA_EXISTS_NOT_PRESENT
int ida_find_first_range(struct ida *ida, unsigned int min, unsigned int max);

static inline bool ida_exists(struct ida *ida, unsigned int id)
{
	return ida_find_first_range(ida, id, id) == id;
}

static inline int ida_find_first(struct ida *ida)
{
	return ida_find_first_range(ida, 0, ~0);
}
#endif
#endif
