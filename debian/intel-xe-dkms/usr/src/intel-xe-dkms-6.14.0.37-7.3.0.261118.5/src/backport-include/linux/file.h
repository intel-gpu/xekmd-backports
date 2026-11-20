/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __BACKPORT_FILE_H
#define __BACKPORT_FILE_H

#include_next<linux/file.h>

#ifndef fd_file
#define fd_file(f)   ((f).file)
#define fd_empty(f)  unlikely((f).file == NULL)
#endif

#ifndef FD_ADD
static inline int __fd_install_get_unused(unsigned int flags, struct file *file)
{
	int fd = get_unused_fd_flags(flags);
	if (fd < 0)
		return fd;
	fd_install(fd, file);
	return fd;
}
#define FD_ADD(flags, file) __fd_install_get_unused(flags, file)
#endif

#endif /* __BACKPORT_FILE_H */
