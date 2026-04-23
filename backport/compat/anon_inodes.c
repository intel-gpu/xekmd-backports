// SPDX-License-Identifier: GPL-2.0-only
/*
 *  fs/anon_inodes.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 *  Thanks to Arnd Bergmann for code review and suggestions.
 *  More changes for Thomas Gleixner suggestions.
 *
 */

#include <linux/anon_inodes.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>

#ifdef BPM_ANON_INODE_GETFILE_FMODE_NOT_PRESENT
/**
 * anon_inode_getfile_fmode - creates a new file instance by hooking it up to an
 *                      anonymous inode, and a dentry that describe the "class"
 *                      of the file
 *
 * @name:    [in]    name of the "class" of the new file
 * @fops:    [in]    file operations for the new file
 * @priv:    [in]    private data for the new file (will be file's private_data)
 * @flags:   [in]    flags
 * @f_mode:  [in]    fmode
 *
 * Creates a new file by hooking it on a single inode. This is useful for files
 * that do not need to have a full-fledged inode in order to operate correctly.
 * All the files created with anon_inode_getfile() will share a single inode,
 * hence saving memory and avoiding code duplication for the file/inode/dentry
 * setup. Allows setting the fmode. Returns the newly created file* or an error
 * pointer.
 */
struct file *anon_inode_getfile_fmode(const char *name,
				const struct file_operations *fops,
				void *priv, int flags, fmode_t f_mode)
{
	struct file *file;

	file = anon_inode_getfile(name, fops, priv, flags);
	if (!IS_ERR(file))
		file->f_mode |= f_mode;

	return file;
}
EXPORT_SYMBOL_GPL(anon_inode_getfile_fmode);
#endif
