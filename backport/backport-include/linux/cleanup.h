/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_CLEANUP_H
#define __BACKPORT_LINUX_CLEANUP_H

#include <linux/errno.h>

#ifdef HAVE_LINUX_CLEANUP_H
#include_next <linux/cleanup.h>
#else

/* Minimal guard() / CLASS() / scoped_guard() compat for kernels < 6.1. */
#ifndef __cleanup
#define __cleanup(func) __attribute__((__cleanup__(func)))
#endif

#ifndef DEFINE_CLASS
#define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)         \
typedef _type class_##_name##_t;                                        \
static inline _type class_##_name##_constructor(_init_args)             \
{ _type t = _init; return t; }                                          \
static inline void class_##_name##_destructor(_type *_T)                \
{ _type t = *_T; (void)t; _exit; }
#endif

#ifndef CLASS
#define CLASS(_name, var)                                               \
        class_##_name##_t var __cleanup(class_##_name##_destructor)     \
                = class_##_name##_constructor
#endif

#ifndef guard
#define guard(_name)                                                    \
        CLASS(_name, __UNIQUE_ID(guard))
#endif

#ifndef scoped_guard
#define scoped_guard(_name, args...)                                    \
        for (CLASS(_name, scope)(args), *done = NULL; !done; done = (void *)1)
#endif

#endif /* LINUX_VERSION_CODE >= 6.1 */

/*
 * Avoid including linux/mutex.h here: mutex.h can include cleanup.h,
 * and this wrapper may be parsed before mutex prototypes are visible.
 */
struct mutex;
extern void mutex_unlock(struct mutex *lock);
extern int mutex_lock_interruptible(struct mutex *lock);

/*
 * Newer kernels provide scoped_cond_guard() together with condition-aware
 * lock classes such as mutex_intr. Provide a minimal backport for 5.15.
 */
#ifndef class_mutex_intr_t
typedef struct {
        struct mutex *lock;
        int err;
} class_mutex_intr_t;

static inline void class_mutex_intr_destructor(class_mutex_intr_t *_T)
{
        if (_T->lock && !_T->err)
                mutex_unlock(_T->lock);
}

static inline class_mutex_intr_t class_mutex_intr_constructor(struct mutex *lock)
{
        class_mutex_intr_t t = {
                .lock = lock,
                .err = mutex_lock_interruptible(lock),
        };

        if (t.err)
                t.lock = NULL;

        return t;
}
#endif

#ifndef scoped_cond_guard
#define scoped_cond_guard(_name, _fail, args...) \
        for (CLASS(_name, scope)(args), *done = NULL; !done; done = (void *)1) \
                if (scope.err) { _fail; } else
#endif

#endif /* __BACKPORT_LINUX_CLEANUP_H */
