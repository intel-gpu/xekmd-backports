// SPDX-License-Identifier: GPL-2.0-only
#include<linux/mm.h>

#ifdef BPM_PIN_USER_PAGES_REMOTE_ARG6_NOT_PRESENT
#undef pin_user_pages_remote
long bkpt_pin_user_pages_remote(struct mm_struct *mm,
			    unsigned long start, unsigned long nr_pages,
			    unsigned int gup_flags, struct page **pages,
			    int *locked)
{
	return pin_user_pages_remote(mm, start, nr_pages, gup_flags, pages, NULL, locked);
}

#define pin_user_pages_remote bkpt_pin_user_pages_remote
EXPORT_SYMBOL(pin_user_pages_remote);

#endif