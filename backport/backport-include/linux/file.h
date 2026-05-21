/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __BACKPORT_FILE_H
#define __BACKPORT_FILE_H

#include_next<linux/file.h>

#ifdef BPM_FD_FILE_FD_EMPTY_NOT_PRESENT
#define fd_file(f)   ((f).file)
#define fd_empty(f)  unlikely((f).file == NULL)
#endif

#endif
