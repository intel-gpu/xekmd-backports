// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

/*
 * 05.04.94  -  Multi-page memory management added for v1.1.
 *              Idea by Alex Bligh (alex@cconcepts.co.uk)
 *
 * 16.07.99  -  Support of BIGMEM added by Gerhard Wichert, Siemens AG
 *		(Gerhard.Wichert@pdb.siemens.de)
 *
 * Aug/Sep 2004 Changed to four level page tables (Andi Kleen)
 */

#include <linux/mm.h>

#if defined(BPM_ACCESS_REMOTE_VM_NOT_PRESENT) || \
    defined(BPM_ACCESS_REMOTE_VM_EXPORT_NOT_PRESENT)
int access_remote_vm(struct mm_struct *mm, unsigned long addr,
        void *buf, int len, unsigned int gup_flags)
{
    struct task_struct *tsk;
    int ret = 0;

    rcu_read_lock();
    for_each_process(tsk) {
        if (tsk->mm == mm) {
            get_task_struct(tsk);
            rcu_read_unlock();
            ret = access_process_vm(tsk, addr, buf, len, gup_flags);
            put_task_struct(tsk);
            return ret;
        }
    }
    rcu_read_unlock();

    return 0;
}

EXPORT_SYMBOL(access_remote_vm);
#endif
