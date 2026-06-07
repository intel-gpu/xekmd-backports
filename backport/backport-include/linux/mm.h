/* SPDX-License-Identifier: MIT */
#ifndef __BACKPORT_LINUX_MM_H
#define __BACKPORT_LINUX_MM_H

#include_next <linux/mm.h>

#if defined(BPM_ACCESS_REMOTE_VM_NOT_PRESENT) || \
    defined(BPM_ACCESS_REMOTE_VM_EXPORT_NOT_PRESENT)
extern int access_remote_vm(struct mm_struct *mm, unsigned long addr,
        void *buf, int len, unsigned int gup_flags);
#endif

#endif /* __BACKPORT_LINUX_MM_H__ */
