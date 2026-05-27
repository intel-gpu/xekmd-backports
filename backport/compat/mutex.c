// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Intel
 *
 * Backport of mutex_lock_interruptible for older kernels
 * where it may be inlined and not available to modules.
 */

#include <linux/mutex.h>

#ifdef BPM_MUTEX_LOCK_INTERRUPTIBLE_NOT_EXPORTED
#undef mutex_lock_interruptible
/**
 * mutex_lock_interruptible() - Acquire the mutex, interruptible by signals.
 * @lock: The mutex to be acquired.
 *
 * Lock the mutex like mutex_lock().  If a signal is delivered while the
 * process is sleeping, this function will return without acquiring the
 * mutex.
 *
 * Context: Process context.
 * Return: 0 if the lock was successfully acquired or %-EINTR if a
 * signal arrived.
 */
int mutex_lock_interruptible(struct mutex *lock)
{
	mutex_lock(lock);
	return 0;
}
EXPORT_SYMBOL(mutex_lock_interruptible);
#endif
