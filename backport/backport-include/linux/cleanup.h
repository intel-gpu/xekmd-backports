/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_CLEANUP_H
#define __BACKPORT_LINUX_CLEANUP_H

#include <linux/errno.h>

#ifdef HAVE_LINUX_CLEANUP_H
#include_next <linux/cleanup.h>
#else

/*
 * v7.0 introduced a 4-argument form of DEFINE_GUARD_COND() with
 * a success condition, plus ACQUIRE()/ACQUIRE_ERR() helpers and
 * the __guard_err() accessor.  Kernel 6.6 only has the 3-arg form.
 *
 * Provide the missing pieces so that xe_pm.h and xe_device.c compile.
 */

#ifdef BPM_CLEANUP_ACQUIRE_NOT_PRESENT

/*
 * __DEFINE_CLASS_IS_CONDITIONAL is a v7.0 sparse-only marker recording
 * whether a guard class is conditional.  On pre-v7.0 kernels it does
 * not exist; provide an empty stub so backport macros below compile.
 */
#ifndef __DEFINE_CLASS_IS_CONDITIONAL
#define __DEFINE_CLASS_IS_CONDITIONAL(_name, _is_cond)
#endif

/* Error-checking guard pointer helpers (v7.0 cleanup.h) */
#define __GUARD_IS_ERR(_ptr)						\
	({								\
		unsigned long _rc = (__force unsigned long)(_ptr);	\
		unlikely((_rc - 1) >= -MAX_ERRNO - 1);			\
	})

#define __DEFINE_GUARD_LOCK_PTR(_name, _exp)				\
	static __always_inline void *					\
	class_##_name##_lock_ptr(class_##_name##_t *_T)			\
	{								\
		void *_ptr = (void *)(__force unsigned long)*(_exp);	\
		if (IS_ERR(_ptr))					\
			_ptr = NULL;					\
		return _ptr;						\
	}								\
	static __always_inline int					\
	class_##_name##_lock_err(class_##_name##_t *_T)			\
	{								\
		long _rc = (__force unsigned long)*(_exp);		\
		if (!_rc)						\
			_rc = -EBUSY;					\
		if (!IS_ERR_VALUE(_rc))					\
			_rc = 0;					\
		return _rc;						\
	}

/* 4-arg DEFINE_GUARD_COND: (_name, _ext, _lock, _cond) */
#define DEFINE_GUARD_COND_4(_name, _ext, _lock, _cond)			\
	__DEFINE_CLASS_IS_CONDITIONAL(_name##_ext, true);		\
	EXTEND_CLASS(_name, _ext,					\
		({ void *_t = _T; int _RET = (_lock);			\
		   if (_T && !(_cond)) _t = ERR_PTR(_RET); _t; }),	\
		class_##_name##_t _T)					\
	static __always_inline void *					\
	class_##_name##_ext##_lock_ptr(class_##_name##_t *_T)		\
	{ return class_##_name##_lock_ptr(_T); }			\
	static __always_inline int					\
	class_##_name##_ext##_lock_err(class_##_name##_t *_T)		\
	{ return class_##_name##_lock_err(_T); }

/* 3-arg form falls through to 4-arg with default condition */
#define DEFINE_GUARD_COND_3(_name, _ext, _lock)				\
	DEFINE_GUARD_COND_4(_name, _ext, _lock, _RET)

/*
 * Override the base DEFINE_GUARD_COND with a variadic dispatcher.
 * The 6.6 kernel only has the 3-arg version; we replace it with
 * a CONCATENATE(DEFINE_GUARD_COND_, COUNT_ARGS(X)) dispatch so
 * both 3- and 4-arg invocations work.
 */
#include <linux/args.h>
#undef DEFINE_GUARD_COND
#define DEFINE_GUARD_COND(X...) CONCATENATE(DEFINE_GUARD_COND_, COUNT_ARGS(X))(X)

/*
 * Override DEFINE_GUARD to produce the error-aware lock_ptr/lock_err
 * helpers needed by ACQUIRE_ERR.
 */
#undef DEFINE_GUARD
#define DEFINE_GUARD(_name, _type, _lock, _unlock)			\
	DEFINE_CLASS(_name, _type,					\
		if (!__GUARD_IS_ERR(_T)) { _unlock; },			\
		({ _lock; _T; }), _type _T);				\
	__DEFINE_CLASS_IS_CONDITIONAL(_name, false);			\
	__DEFINE_GUARD_LOCK_PTR(_name, _T)

#define __guard_err(_name) class_##_name##_lock_err

#define ACQUIRE(_name, _var)     CLASS(_name, _var)
#define ACQUIRE_ERR(_name, _var) __guard_err(_name)(_var)

#endif /* BPM_CLEANUP_ACQUIRE_NOT_PRESENT */

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

#ifndef scoped_cond_guard
struct mutex;
extern void mutex_unlock(struct mutex *lock);
extern int mutex_lock_interruptible(struct mutex *lock);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
extern int mutex_lock_interruptible_nested(struct mutex *lock,
					   unsigned int subclass);
#endif

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
#ifdef CONFIG_DEBUG_LOCK_ALLOC
		.err = mutex_lock_interruptible_nested(lock, 0),
#else
                .err = mutex_lock_interruptible(lock),
#endif
        };

        if (t.err)
                t.lock = NULL;

        return t;
}
#endif

#define scoped_cond_guard(_name, _fail, args...) \
        for (CLASS(_name, scope)(args), *done = NULL; !done; done = (void *)1) \
                if (scope.err) { _fail; } else
#endif

#endif /* !HAVE_LINUX_CLEANUP_H */

#endif /* __BACKPORT_LINUX_CLEANUP_H */
