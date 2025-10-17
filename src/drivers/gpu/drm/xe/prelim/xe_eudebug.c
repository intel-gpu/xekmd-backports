// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */

#include <linux/anon_inodes.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <drm/drm_drv.h>
#include <drm/drm_managed.h>

#include <generated/xe_wa_oob.h>

#include "regs/xe_gt_regs.h"
#include "regs/xe_engine_regs.h"

#include "xe_assert.h"
#include "xe_bo.h"
#include "xe_debug_metadata.h"
#include "xe_device.h"
#include "xe_debug_metadata.h"
#include "prelim/xe_eudebug.h"
#include "prelim/xe_eudebug_types.h"
#include "xe_exec_queue.h"
#include "xe_exec_queue_types.h"
#include "xe_force_wake.h"
#include "xe_gt.h"
#include "xe_gt_debug.h"
#include "xe_gt_mcr.h"
#include "xe_gt_pagefault.h"
#include "xe_guc_exec_queue_types.h"
#include "xe_hw_engine.h"
#include "xe_lrc.h"
#include "xe_macros.h"
#include "xe_mmio.h"
#include "xe_pm.h"
#include "xe_reg_sr.h"
#include "xe_rtp.h"
#include "xe_sched_job.h"
#include "xe_sync.h"
#include "xe_vm.h"
#include "xe_wa.h"

/*
 * If there is no detected event read by userspace, during this period, assume
 * userspace problem and disconnect debugger to allow forward progress.
 */
#define XE_EUDEBUG_NO_READ_DETECTED_TIMEOUT_MS (25 * 1000)

#define for_each_debugger_rcu(debugger, head) \
	list_for_each_entry_rcu((debugger), (head), connection_link)
#define for_each_debugger(debugger, head) \
	list_for_each_entry((debugger), (head), connection_link)

#define cast_event(T, event) container_of((event), typeof(*(T)), base)

#define XE_EUDEBUG_DBG_STR "eudbg: %lld:%lu:%s (%d/%d) -> (%d/%d): "
#define XE_EUDEBUG_DBG_ARGS(d) (d)->session, \
		atomic_long_read(&(d)->events.seqno), \
		READ_ONCE(d->connection.status) <= 0 ? "disconnected" : "", \
		current->pid, \
		task_tgid_nr(current), \
		(d)->target_task->pid, \
		task_tgid_nr((d)->target_task)

#define eu_err(d, fmt, ...) drm_err(&(d)->xe->drm, XE_EUDEBUG_DBG_STR # fmt, \
				    XE_EUDEBUG_DBG_ARGS(d), ##__VA_ARGS__)
#define eu_warn(d, fmt, ...) drm_warn(&(d)->xe->drm, XE_EUDEBUG_DBG_STR # fmt, \
				      XE_EUDEBUG_DBG_ARGS(d), ##__VA_ARGS__)
#define eu_dbg(d, fmt, ...) drm_dbg(&(d)->xe->drm, XE_EUDEBUG_DBG_STR # fmt, \
				    XE_EUDEBUG_DBG_ARGS(d), ##__VA_ARGS__)

#define xe_eudebug_assert(d, ...) xe_assert((d)->xe, ##__VA_ARGS__)

#define struct_member(T, member) (((T *)0)->member)

/* Keep 1:1 parity with uapi events */
#define write_member(T_out, ptr, member, value) { \
	BUILD_BUG_ON(sizeof(*ptr) != sizeof(T_out)); \
	BUILD_BUG_ON(offsetof(typeof(*ptr), member) != \
		     offsetof(typeof(T_out), member)); \
	BUILD_BUG_ON(sizeof(ptr->member) != sizeof(value)); \
	BUILD_BUG_ON(sizeof(struct_member(T_out, member)) != sizeof(value)); \
	BUILD_BUG_ON(!typecheck(typeof((ptr)->member), value));	\
	(ptr)->member = (value); \
	}

static struct xe_eudebug_event *
event_fifo_pending(struct xe_eudebug *d)
{
	struct xe_eudebug_event *event;

	if (kfifo_peek(&d->events.fifo, &event))
		return event;

	return NULL;
}

/*
 * This is racy as we dont take the lock for read but all the
 * callsites can handle the race so we can live without lock.
 */
__no_kcsan
static unsigned int
event_fifo_num_events_peek(const struct xe_eudebug * const d)
{
	return kfifo_len(&d->events.fifo);
}

static bool
xe_eudebug_detached(struct xe_eudebug *d)
{
	int status;

	spin_lock(&d->connection.lock);
	status = d->connection.status;
	spin_unlock(&d->connection.lock);

	return status <= 0;
}

static int
xe_eudebug_error(const struct xe_eudebug * const d)
{
	const int status = READ_ONCE(d->connection.status);

	return status <= 0 ? status : 0;
}

static unsigned int
event_fifo_has_events(struct xe_eudebug *d)
{
	if (xe_eudebug_detached(d))
		return 1;

	return event_fifo_num_events_peek(d);
}

static const struct rhashtable_params rhash_res = {
	.head_offset = offsetof(struct xe_eudebug_handle, rh_head),
	.key_len = sizeof_field(struct xe_eudebug_handle, key),
	.key_offset = offsetof(struct xe_eudebug_handle, key),
	.automatic_shrinking = true,
};

static struct xe_eudebug_resource *
resource_from_type(struct xe_eudebug_resources * const res, const int t)
{
	return &res->rt[t];
}

static struct xe_eudebug_resources *
xe_eudebug_resources_alloc(void)
{
	struct xe_eudebug_resources *res;
	int err;
	int i;

	res = kzalloc(sizeof(*res), GFP_ATOMIC);
	if (!res)
		return ERR_PTR(-ENOMEM);

	mutex_init(&res->lock);

	for (i = 0; i < XE_EUDEBUG_RES_TYPE_COUNT; i++) {
		xa_init_flags(&res->rt[i].xa, XA_FLAGS_ALLOC1);
		err = rhashtable_init(&res->rt[i].rh, &rhash_res);

		if (err)
			break;
	}

	if (err) {
		while (i--) {
			xa_destroy(&res->rt[i].xa);
			rhashtable_destroy(&res->rt[i].rh);
		}

		kfree(res);
		return ERR_PTR(err);
	}

	return res;
}

static void res_free_fn(void *ptr, void *arg)
{
	XE_WARN_ON(ptr);
	kfree(ptr);
}

static void
xe_eudebug_destroy_resources(struct xe_eudebug *d)
{
	struct xe_eudebug_resources *res = d->res;
	struct xe_eudebug_handle *h;
	unsigned long j;
	int i;
	int err;

	mutex_lock(&res->lock);
	for (i = 0; i < XE_EUDEBUG_RES_TYPE_COUNT; i++) {
		struct xe_eudebug_resource *r = &res->rt[i];

		xa_for_each(&r->xa, j, h) {
			struct xe_eudebug_handle *t;

			err = rhashtable_remove_fast(&r->rh,
						     &h->rh_head,
						     rhash_res);
			xe_eudebug_assert(d, !err);
			t = xa_erase(&r->xa, h->id);
			xe_eudebug_assert(d, t == h);
			kfree(t);
		}
	}
	mutex_unlock(&res->lock);

	for (i = 0; i < XE_EUDEBUG_RES_TYPE_COUNT; i++) {
		struct xe_eudebug_resource *r = &res->rt[i];

		rhashtable_free_and_destroy(&r->rh, res_free_fn, NULL);
		xe_eudebug_assert(d, xa_empty(&r->xa));
		xa_destroy(&r->xa);
	}

	mutex_destroy(&res->lock);

	kfree(res);
}

static void xe_eudebug_free(struct kref *ref)
{
	struct xe_eudebug *d = container_of(ref, typeof(*d), ref);
	struct xe_eudebug_event *event;
	struct xe_eudebug_pagefault *pf, *pf_temp;

	while (kfifo_get(&d->events.fifo, &event))
		kfree(event);

	/* Since it's the last reference no race here */
	list_for_each_entry_safe(pf, pf_temp, &d->pagefaults, list) {
		xe_exec_queue_put(pf->q);
		kfree(pf);
	}

	xe_eudebug_destroy_resources(d);
	put_task_struct(d->target_task);

	xe_eudebug_assert(d, !kfifo_len(&d->events.fifo));

	kfree_rcu(d, rcu);
}

void prelim_xe_eudebug_put(struct xe_eudebug *d)
{
	kref_put(&d->ref, xe_eudebug_free);
}

struct xe_eudebug_ack {
	struct rb_node rb_node;
	u64 seqno;
	u64 ts_insert;
	struct xe_user_fence *ufence;
};

#define fetch_ack(x) rb_entry(x, struct xe_eudebug_ack, rb_node)

static int compare_ack(const u64 a, const u64 b)
{
	if (a < b)
		return -1;
	else if (a > b)
		return 1;

	return 0;
}

static int ack_insert_cmp(struct rb_node * const node,
			  const struct rb_node * const p)
{
	return compare_ack(fetch_ack(node)->seqno,
			   fetch_ack(p)->seqno);
}

static int ack_lookup_cmp(const void * const key,
			  const struct rb_node * const node)
{
	return compare_ack(*(const u64 *)key,
			   fetch_ack(node)->seqno);
}

static struct xe_eudebug_ack *remove_ack(struct xe_eudebug *d, u64 seqno)
{
	struct rb_root * const root = &d->acks.tree;
	struct rb_node *node;

	spin_lock(&d->acks.lock);
	node = rb_find(&seqno, root, ack_lookup_cmp);
	if (node)
		rb_erase(node, root);
	spin_unlock(&d->acks.lock);

	if (!node)
		return NULL;

	return rb_entry_safe(node, struct xe_eudebug_ack, rb_node);
}

static void ufence_signal_worker(struct work_struct *w)
{
	struct xe_user_fence * const ufence =
		container_of(w, struct xe_user_fence, eudebug.worker);

	if (READ_ONCE(ufence->signalled))
		xe_sync_ufence_signal(ufence);

	xe_sync_ufence_put(ufence);
}

static void kick_ufence_worker(struct xe_user_fence *f)
{
	queue_work(f->xe->eudebug.ordered_wq, &f->eudebug.worker);
}

static void handle_ack(struct xe_eudebug *d, struct xe_eudebug_ack *ack,
		       bool on_disconnect)
{
	struct xe_user_fence *f = ack->ufence;
	u64 signalled_by;
	bool signal = false;

	spin_lock(&f->eudebug.lock);
	if (!f->eudebug.signalled_seqno) {
		f->eudebug.signalled_seqno = ack->seqno;
		signal = true;
	}
	signalled_by = f->eudebug.signalled_seqno;
	spin_unlock(&f->eudebug.lock);

	if (signal)
		kick_ufence_worker(f);
	else
		xe_sync_ufence_put(f);

	eu_dbg(d, "ACK: seqno=%llu: signalled by %llu (%s) (held %lluus)",
	       ack->seqno, signalled_by,
	       on_disconnect ? "disconnect" : "debugger",
	       ktime_us_delta(ktime_get(), ack->ts_insert));

	kfree(ack);
}

static void release_acks(struct xe_eudebug *d)
{
	struct xe_eudebug_ack *ack, *n;
	struct rb_root root;

	spin_lock(&d->acks.lock);
	root = d->acks.tree;
	d->acks.tree = RB_ROOT;
	spin_unlock(&d->acks.lock);

	rbtree_postorder_for_each_entry_safe(ack, n, &root, rb_node)
		handle_ack(d, ack, true);
}

static struct task_struct *find_get_target(const pid_t nr)
{
	struct task_struct *task;

	rcu_read_lock();
	task = pid_task(find_pid_ns(nr, task_active_pid_ns(current)), PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	return task;
}

static int
xe_eudebug_attach(struct xe_device *xe, struct xe_eudebug *d,
		  const pid_t pid_nr)
{
	struct task_struct *target;
	struct xe_eudebug *iter;
	int ret = 0;

	target = find_get_target(pid_nr);
	if (!target)
		return -ENOENT;

	if (!ptrace_may_access(target, PTRACE_MODE_READ_REALCREDS)) {
		put_task_struct(target);
		return -EACCES;
	}

	XE_WARN_ON(d->connection.status != 0);

	spin_lock(&xe->eudebug.lock);
	for_each_debugger(iter, &xe->eudebug.list) {
		if (!same_thread_group(iter->target_task, target))
			continue;

		ret = -EBUSY;
	}

	if (!ret && xe->eudebug.session_count + 1 == 0)
		ret = -ENOSPC;

	if (!ret) {
		d->connection.status = XE_EUDEBUG_STATUS_CONNECTED;
		d->xe = xe;
		d->target_task = get_task_struct(target);
		d->session = ++xe->eudebug.session_count;
		kref_get(&d->ref);
		list_add_tail_rcu(&d->connection_link, &xe->eudebug.list);
	}
	spin_unlock(&xe->eudebug.lock);

	put_task_struct(target);

	return ret;
}

static bool xe_eudebug_detach(struct xe_device *xe,
			      struct xe_eudebug *d,
			      const int err)
{
	bool detached = false;

	XE_WARN_ON(err > 0);

	spin_lock(&d->connection.lock);
	if (d->connection.status == XE_EUDEBUG_STATUS_CONNECTED) {
		d->connection.status = err;
		detached = true;
	}
	spin_unlock(&d->connection.lock);

	flush_work(&d->discovery_work);

	if (!detached)
		return false;

	spin_lock(&xe->eudebug.lock);
	list_del_rcu(&d->connection_link);
	spin_unlock(&xe->eudebug.lock);

	eu_dbg(d, "session %lld detached with %d", d->session, err);

	release_acks(d);

	/* Our ref with the connection_link */
	prelim_xe_eudebug_put(d);

	return true;
}

static int _xe_eudebug_disconnect(struct xe_eudebug *d,
				  const int err)
{
	wake_up_all(&d->events.write_done);
	wake_up_all(&d->events.read_done);

	return xe_eudebug_detach(d->xe, d, err);
}

#define xe_eudebug_disconnect(_d, _err) ({ \
	if (_xe_eudebug_disconnect((_d), (_err))) { \
		if ((_err) == 0 || (_err) == -ETIMEDOUT) \
			eu_dbg(d, "Session closed (%d)", (_err)); \
		else \
			eu_err(d, "Session disconnected, err = %d (%s:%d)", \
			       (_err), __func__, __LINE__); \
	} \
})

static int xe_eudebug_release(struct inode *inode, struct file *file)
{
	struct xe_eudebug *d = file->private_data;

	xe_eudebug_disconnect(d, 0);
	prelim_xe_eudebug_put(d);

	return 0;
}

static __poll_t xe_eudebug_poll(struct file *file, poll_table *wait)
{
	struct xe_eudebug * const d = file->private_data;
	__poll_t ret = 0;

	poll_wait(file, &d->events.write_done, wait);

	if (xe_eudebug_detached(d)) {
		ret |= EPOLLHUP;
		if (xe_eudebug_error(d))
			ret |= EPOLLERR;
	}

	if (event_fifo_num_events_peek(d))
		ret |= EPOLLIN;

	return ret;
}

static ssize_t xe_eudebug_read(struct file *file,
			       char __user *buf,
			       size_t count,
			       loff_t *ppos)
{
	return -EINVAL;
}

static struct xe_eudebug *
xe_eudebug_for_task_get(struct xe_device *xe,
			struct task_struct *task)
{
	struct xe_eudebug *d, *iter;

	d = NULL;

	rcu_read_lock();
	for_each_debugger_rcu(iter, &xe->eudebug.list) {
		if (!same_thread_group(iter->target_task, task))
			continue;

		if (kref_get_unless_zero(&iter->ref))
			d = iter;

		break;
	}
	rcu_read_unlock();

	return d;
}

static struct task_struct *find_task_get(struct xe_file *xef)
{
	struct task_struct *task;
	struct pid *pid;

	rcu_read_lock();
	pid = rcu_dereference(xef->drm->pid);
	task = pid_task(pid, PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	return task;
}

static struct xe_eudebug *
_xe_eudebug_get(struct xe_file *xef)
{
	struct task_struct *task;
	struct xe_eudebug *d;

	d = NULL;
	task = find_task_get(xef);
	if (task) {
		d = xe_eudebug_for_task_get(to_xe_device(xef->drm->minor->dev),
					    task);
		put_task_struct(task);
	}

	if (!d)
		return NULL;

	if (xe_eudebug_detached(d)) {
		prelim_xe_eudebug_put(d);
		return NULL;
	}

	return d;
}

struct xe_eudebug *
prelim_xe_eudebug_get(struct xe_file *xef)
{
	struct xe_eudebug *d;

	lockdep_assert_held(&xef->xe->eudebug.discovery_lock);

	d = _xe_eudebug_get(xef);
	if (d) {
		if (!completion_done(&d->discovery)) {
			prelim_xe_eudebug_put(d);
			d = NULL;
		}
	}

	return d;
}

static int xe_eudebug_queue_event(struct xe_eudebug *d,
				  struct xe_eudebug_event *event)
{
	const u64 wait_jiffies = msecs_to_jiffies(1000);
	u64 last_read_detected_ts, last_head_seqno, start_ts;

	xe_eudebug_assert(d, event->len > sizeof(struct xe_eudebug_event));
	xe_eudebug_assert(d, event->type);
	xe_eudebug_assert(d, event->type != PRELIM_DRM_XE_EUDEBUG_EVENT_READ);

	start_ts = ktime_get();
	last_read_detected_ts = start_ts;
	last_head_seqno = 0;

	do  {
		struct xe_eudebug_event *head;
		u64 head_seqno;
		bool was_queued;

		if (xe_eudebug_detached(d))
			break;

		spin_lock(&d->events.lock);
		head = event_fifo_pending(d);
		if (head)
			head_seqno = event->seqno;
		else
			head_seqno = 0;

		was_queued = kfifo_in(&d->events.fifo, &event, 1);
		spin_unlock(&d->events.lock);

		wake_up_all(&d->events.write_done);

		if (was_queued) {
			event = NULL;
			break;
		}

		XE_WARN_ON(!head_seqno);

		/* If we detect progress, restart timeout */
		if (last_head_seqno != head_seqno)
			last_read_detected_ts = ktime_get();

		last_head_seqno = head_seqno;

		wait_event_interruptible_timeout(d->events.read_done,
						 !kfifo_is_full(&d->events.fifo),
						 wait_jiffies);

	} while (ktime_ms_delta(ktime_get(), last_read_detected_ts) <
		 XE_EUDEBUG_NO_READ_DETECTED_TIMEOUT_MS);

	if (event) {
		eu_dbg(d,
		       "event %llu queue failed (blocked %lld ms, avail %d)",
		       event ? event->seqno : 0,
		       ktime_ms_delta(ktime_get(), start_ts),
		       kfifo_avail(&d->events.fifo));

		kfree(event);

		return -ETIMEDOUT;
	}

	return 0;
}

static struct xe_eudebug_handle *
alloc_handle(const int type, const u64 key)
{
	struct xe_eudebug_handle *h;

	h = kzalloc(sizeof(*h), GFP_ATOMIC);
	if (!h)
		return NULL;

	h->key = key;

	return h;
}

static struct xe_eudebug_handle *
__find_handle(struct xe_eudebug_resource *r,
	      const u64 key)
{
	struct xe_eudebug_handle *h;

	h = rhashtable_lookup_fast(&r->rh,
				   &key,
				   rhash_res);
	return h;
}

static int find_handle(struct xe_eudebug_resources *res,
		       const int type,
		       const void *p)
{
	const u64 key = (uintptr_t)p;
	struct xe_eudebug_resource *r;
	struct xe_eudebug_handle *h;
	int id;

	if (XE_WARN_ON(!key))
		return -EINVAL;

	r = resource_from_type(res, type);

	mutex_lock(&res->lock);
	h = __find_handle(r, key);
	id = h ? h->id : -ENOENT;
	mutex_unlock(&res->lock);

	return id;
}

static void *find_resource__unlocked(struct xe_eudebug_resources *res,
				     const int type,
				     const u32 id)
{
	struct xe_eudebug_resource *r;
	struct xe_eudebug_handle *h;

	r = resource_from_type(res, type);
	h = xa_load(&r->xa, id);

	return h ? (void *)(uintptr_t)h->key : NULL;
}

static void *find_resource(struct xe_eudebug_resources *res,
			   const int type,
			   const u32 id)
{
	void *p;

	mutex_lock(&res->lock);
	p =  find_resource__unlocked(res, type, id);
	mutex_unlock(&res->lock);

	return p;
}

static struct xe_file *find_client_get(struct xe_eudebug *d, const u32 id)
{
	struct xe_file *xef;

	mutex_lock(&d->res->lock);
	xef = find_resource__unlocked(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, id);
	if (xef)
		xe_file_get(xef);
	mutex_unlock(&d->res->lock);

	return xef;
}

static struct xe_exec_queue *find_exec_queue_get(struct xe_eudebug *d,
						 u32 id)
{
	struct xe_exec_queue *q;

	mutex_lock(&d->res->lock);
	q = find_resource__unlocked(d->res, XE_EUDEBUG_RES_TYPE_EXEC_QUEUE, id);
	if (q)
		xe_exec_queue_get(q);
	mutex_unlock(&d->res->lock);

	return q;
}

static struct xe_lrc *find_lrc(struct xe_eudebug *d, const u32 id)
{
	return find_resource(d->res, XE_EUDEBUG_RES_TYPE_LRC, id);
}

static int _xe_eudebug_add_handle(struct xe_eudebug *d,
				  int type,
				  void *p,
				  u64 *seqno,
				  int *handle)
{
	const u64 key = (uintptr_t)p;
	struct xe_eudebug_resource *r;
	struct xe_eudebug_handle *h, *o;
	int err;

	if (XE_WARN_ON(!p))
		return -EINVAL;

	if (xe_eudebug_detached(d))
		return -ENOTCONN;

	h = alloc_handle(type, key);
	if (!h)
		return -ENOMEM;

	r = resource_from_type(d->res, type);

	mutex_lock(&d->res->lock);
	o = __find_handle(r, key);
	if (!o) {
		err = xa_alloc(&r->xa, &h->id, h, xa_limit_31b, GFP_KERNEL);

		if (h->id >= INT_MAX) {
			xa_erase(&r->xa, h->id);
			err = -ENOSPC;
		}

		if (!err)
			err = rhashtable_insert_fast(&r->rh,
						     &h->rh_head,
						     rhash_res);

		if (err) {
			xa_erase(&r->xa, h->id);
		} else {
			if (seqno)
				*seqno = atomic_long_inc_return(&d->events.seqno);
		}
	} else {
		xe_eudebug_assert(d, o->id);
		err = -EEXIST;
	}
	mutex_unlock(&d->res->lock);

	if (handle)
		*handle = o ? o->id : h->id;

	if (err) {
		kfree(h);
		XE_WARN_ON(err > 0);
		return err;
	}

	xe_eudebug_assert(d, h->id);

	return h->id;
}

static int xe_eudebug_add_handle(struct xe_eudebug *d,
				 int type,
				 void *p,
				 u64 *seqno)
{
	int ret;

	ret = _xe_eudebug_add_handle(d, type, p, seqno, NULL);
	if (ret == -EEXIST || ret == -ENOTCONN) {
		eu_dbg(d, "%d on adding %d", ret, type);
		return 0;
	}

	if (ret < 0)
		xe_eudebug_disconnect(d, ret);

	return ret;
}

static int _xe_eudebug_remove_handle(struct xe_eudebug *d, int type, void *p,
				     u64 *seqno)
{
	const u64 key = (uintptr_t)p;
	struct xe_eudebug_resource *r;
	struct xe_eudebug_handle *h, *xa_h;
	int ret;

	if (XE_WARN_ON(!key))
		return -EINVAL;

	if (xe_eudebug_detached(d))
		return -ENOTCONN;

	r = resource_from_type(d->res, type);

	mutex_lock(&d->res->lock);
	h = __find_handle(r, key);
	if (h) {
		ret = rhashtable_remove_fast(&r->rh,
					     &h->rh_head,
					     rhash_res);
		xe_eudebug_assert(d, !ret);
		xa_h = xa_erase(&r->xa, h->id);
		xe_eudebug_assert(d, xa_h == h);
		if (!ret) {
			ret = h->id;
			if (seqno)
				*seqno = atomic_long_inc_return(&d->events.seqno);
		}
	} else {
		ret = -ENOENT;
	}
	mutex_unlock(&d->res->lock);

	kfree(h);

	xe_eudebug_assert(d, ret);

	return ret;
}

static int xe_eudebug_remove_handle(struct xe_eudebug *d, int type, void *p,
				    u64 *seqno)
{
	int ret;

	ret = _xe_eudebug_remove_handle(d, type, p, seqno);
	if (ret == -ENOENT || ret == -ENOTCONN) {
		eu_dbg(d, "%d on removing %d", ret, type);
		return 0;
	}

	if (ret < 0)
		xe_eudebug_disconnect(d, ret);

	return ret;
}

static struct xe_eudebug_event *
xe_eudebug_create_event(struct xe_eudebug *d, u16 type, u64 seqno, u16 flags,
			u32 len)
{
	const u16 max_event = PRELIM_DRM_XE_EUDEBUG_EVENT_EXEC_QUEUE_PLACEMENTS;
	const u16 known_flags =
		PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE |
		PRELIM_DRM_XE_EUDEBUG_EVENT_DESTROY |
		PRELIM_DRM_XE_EUDEBUG_EVENT_STATE_CHANGE |
		PRELIM_DRM_XE_EUDEBUG_EVENT_NEED_ACK;
	struct xe_eudebug_event *event;

	BUILD_BUG_ON(type > max_event);

	xe_eudebug_assert(d, type <= max_event);
	xe_eudebug_assert(d, !(~known_flags & flags));
	xe_eudebug_assert(d, len > sizeof(*event));

	event = kzalloc(len, GFP_KERNEL);
	if (!event)
		return NULL;

	event->len = len;
	event->type = type;
	event->flags = flags;
	event->seqno = seqno;

	return event;
}

static long xe_eudebug_read_event(struct xe_eudebug *d,
				  const u64 arg,
				  const bool wait)
{
	struct xe_device *xe = d->xe;
	struct prelim_drm_xe_eudebug_event __user * const user_orig =
		u64_to_user_ptr(arg);
	struct prelim_drm_xe_eudebug_event user_event;
	struct xe_eudebug_event *event;
	const unsigned int max_event = PRELIM_DRM_XE_EUDEBUG_EVENT_PAGEFAULT;
	long ret = 0;

	if (XE_IOCTL_DBG(xe, copy_from_user(&user_event, user_orig, sizeof(user_event))))
		return -EFAULT;

	if (XE_IOCTL_DBG(xe, !user_event.type))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, user_event.type > max_event))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, user_event.type != PRELIM_DRM_XE_EUDEBUG_EVENT_READ))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, user_event.len < sizeof(*user_orig)))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, user_event.flags))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, user_event.reserved))
		return -EINVAL;

	/* XXX: define wait time in connect arguments ? */
	if (wait) {
		ret = wait_event_interruptible_timeout(d->events.write_done,
						       event_fifo_has_events(d),
						       msecs_to_jiffies(5 * 1000));

		if (XE_IOCTL_DBG(xe, ret < 0))
			return ret;
	}

	ret = 0;
	spin_lock(&d->events.lock);
	event = event_fifo_pending(d);
	if (event) {
		if (user_event.len < event->len) {
			ret = -EMSGSIZE;
		} else if (!kfifo_out(&d->events.fifo, &event, 1)) {
			eu_warn(d, "internal fifo corruption");
			ret = -ENOTCONN;
		}
	}
	spin_unlock(&d->events.lock);

	wake_up_all(&d->events.read_done);

	if (ret == -EMSGSIZE && put_user(event->len, &user_orig->len))
		ret = -EFAULT;

	if (XE_IOCTL_DBG(xe, ret))
		return ret;

	if (!event) {
		if (xe_eudebug_detached(d))
			return -ENOTCONN;
		if (!wait)
			return -EAGAIN;

		return -ENOENT;
	}

	if (copy_to_user(user_orig, event, event->len))
		ret = -EFAULT;
	else
		eu_dbg(d, "event read: type=%u, flags=0x%x, seqno=%llu", event->type,
		       event->flags, event->seqno);

	kfree(event);

	return ret;
}

static long
xe_eudebug_ack_event_ioctl(struct xe_eudebug *d,
			   const unsigned int cmd,
			   const u64 arg)
{
	struct prelim_drm_xe_eudebug_ack_event __user * const user_ptr =
		u64_to_user_ptr(arg);
	struct prelim_drm_xe_eudebug_ack_event user_arg;
	struct xe_eudebug_ack *ack;
	struct xe_device *xe = d->xe;

	if (XE_IOCTL_DBG(xe, _IOC_SIZE(cmd) < sizeof(user_arg)))
		return -EINVAL;

	/* Userland write */
	if (XE_IOCTL_DBG(xe, !(_IOC_DIR(cmd) & _IOC_WRITE)))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, copy_from_user(&user_arg,
					    user_ptr,
					    sizeof(user_arg))))
		return -EFAULT;

	if (XE_IOCTL_DBG(xe, user_arg.flags))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, xe_eudebug_detached(d)))
		return -ENOTCONN;

	ack = remove_ack(d, user_arg.seqno);
	if (XE_IOCTL_DBG(xe, !ack))
		return -EINVAL;

	handle_ack(d, ack, false);

	return 0;
}

static int do_eu_control(struct xe_eudebug *d,
			 const struct prelim_drm_xe_eudebug_eu_control * const arg,
			 struct prelim_drm_xe_eudebug_eu_control __user * const user_ptr)
{
	void __user * const bitmask_ptr = u64_to_user_ptr(arg->bitmask_ptr);
	struct xe_device *xe = d->xe;
	u8 *bits = NULL;
	unsigned int hw_attn_size, attn_size;
	struct dma_fence *pf_fence;
	struct xe_exec_queue *q;
	struct xe_file *xef;
	struct xe_lrc *lrc;
	u64 seqno;
	int ret;

	if (xe_eudebug_detached(d))
		return -ENOTCONN;

	/* Accept only hardware reg granularity mask */
	if (XE_IOCTL_DBG(xe, !IS_ALIGNED(arg->bitmask_size, sizeof(u32))))
		return -EINVAL;

	xef = find_client_get(d, arg->client_handle);
	if (XE_IOCTL_DBG(xe, !xef))
		return -EINVAL;

	q = find_exec_queue_get(d, arg->exec_queue_handle);
	if (XE_IOCTL_DBG(xe, !q)) {
		xe_file_put(xef);
		return -EINVAL;
	}

	if (XE_IOCTL_DBG(xe, !xe_exec_queue_is_debuggable(q))) {
		ret = -EINVAL;
		goto queue_put;
	}

	if (XE_IOCTL_DBG(xe, xef != q->vm->xef)) {
		ret = -EINVAL;
		goto queue_put;
	}

	lrc = find_lrc(d, arg->lrc_handle);
	if (XE_IOCTL_DBG(xe, !lrc)) {
		ret = -EINVAL;
		goto queue_put;
	}

	hw_attn_size = prelim_xe_gt_eu_attention_bitmap_size(q->gt);
	attn_size = arg->bitmask_size;

	if (attn_size > hw_attn_size)
		attn_size = hw_attn_size;

	if (attn_size > 0) {
		bits = kmalloc(attn_size, GFP_KERNEL);
		if (!bits) {
			ret =  -ENOMEM;
			goto queue_put;
		}

		if (copy_from_user(bits, bitmask_ptr, attn_size)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	if (!pm_runtime_active(xe->drm.dev)) {
		ret = -EIO;
		goto out_free;
	}

	ret = -EINVAL;
	mutex_lock(&d->eu_lock);
	rcu_read_lock();
	pf_fence = dma_fence_get_rcu_safe(&d->pf_fence);
	rcu_read_unlock();

	while (pf_fence) {
		mutex_unlock(&d->eu_lock);
		ret = dma_fence_wait(pf_fence, true);
		dma_fence_put(pf_fence);

		if (ret)
			goto out_free;

		mutex_lock(&d->eu_lock);
		rcu_read_lock();
		pf_fence = dma_fence_get_rcu_safe(&d->pf_fence);
		rcu_read_unlock();
	}

	switch (arg->cmd) {
	case PRELIM_DRM_XE_EUDEBUG_EU_CONTROL_CMD_INTERRUPT_ALL:
		/* Make sure we dont promise anything but interrupting all */
		if (!attn_size)
			ret = d->ops->interrupt_all(d, q, lrc);
		break;
	case PRELIM_DRM_XE_EUDEBUG_EU_CONTROL_CMD_STOPPED:
		ret = d->ops->stopped(d, q, lrc, bits, attn_size);
		break;
	case PRELIM_DRM_XE_EUDEBUG_EU_CONTROL_CMD_RESUME:
		ret = d->ops->resume(d, q, lrc, bits, attn_size);
		break;
	default:
		break;
	}

	if (ret == 0)
		seqno = atomic_long_inc_return(&d->events.seqno);

	mutex_unlock(&d->eu_lock);

	if (ret)
		goto out_free;

	if (put_user(seqno, &user_ptr->seqno)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (copy_to_user(bitmask_ptr, bits, attn_size)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (hw_attn_size != arg->bitmask_size)
		if (put_user(hw_attn_size, &user_ptr->bitmask_size))
			ret = -EFAULT;

out_free:
	kfree(bits);
queue_put:
	xe_exec_queue_put(q);
	xe_file_put(xef);

	return ret;
}

static long xe_eudebug_eu_control(struct xe_eudebug *d, const u64 arg)
{
	struct prelim_drm_xe_eudebug_eu_control __user * const user_ptr =
		u64_to_user_ptr(arg);
	struct prelim_drm_xe_eudebug_eu_control user_arg;
	struct xe_device *xe = d->xe;
	struct xe_file *xef;
	int ret;

	if (XE_IOCTL_DBG(xe, !(_IOC_DIR(PRELIM_DRM_XE_EUDEBUG_IOCTL_EU_CONTROL) & _IOC_WRITE)))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, !(_IOC_DIR(PRELIM_DRM_XE_EUDEBUG_IOCTL_EU_CONTROL) & _IOC_READ)))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, _IOC_SIZE(PRELIM_DRM_XE_EUDEBUG_IOCTL_EU_CONTROL) != sizeof(user_arg)))
		return -EINVAL;

	if (copy_from_user(&user_arg,
			   user_ptr,
			   sizeof(user_arg)))
		return -EFAULT;

	if (XE_IOCTL_DBG(xe, user_arg.flags))
		return -EINVAL;

	if (!access_ok(u64_to_user_ptr(user_arg.bitmask_ptr), user_arg.bitmask_size))
		return -EFAULT;

	eu_dbg(d,
	       "eu_control: client_handle=%llu, cmd=%u, flags=0x%x, exec_queue_handle=%llu, bitmask_size=%u\n",
	       user_arg.client_handle, user_arg.cmd, user_arg.flags, user_arg.exec_queue_handle,
	       user_arg.bitmask_size);

	xef = find_client_get(d, user_arg.client_handle);
	if (XE_IOCTL_DBG(xe, !xef))
		return -EINVAL; /* As this is user input */

	ret = do_eu_control(d, &user_arg, user_ptr);

	xe_file_put(xef);

	eu_dbg(d,
	       "eu_control: client_handle=%llu, cmd=%u, flags=0x%x, exec_queue_handle=%llu, bitmask_size=%u ret=%d\n",
	       user_arg.client_handle, user_arg.cmd, user_arg.flags, user_arg.exec_queue_handle,
	       user_arg.bitmask_size, ret);

	return ret;
}

static struct prelim_xe_debug_metadata *find_metadata_get(struct xe_eudebug *d,
						   u32 id)
{
	struct prelim_xe_debug_metadata *m;

	mutex_lock(&d->res->lock);
	m = find_resource__unlocked(d->res, XE_EUDEBUG_RES_TYPE_METADATA, id);
	if (m)
		kref_get(&m->refcount);
	mutex_unlock(&d->res->lock);

	return m;
}

static long xe_eudebug_read_metadata(struct xe_eudebug *d,
				     unsigned int cmd,
				     const u64 arg)
{
	struct prelim_drm_xe_eudebug_read_metadata user_arg;
	struct prelim_xe_debug_metadata *mdata;
	struct xe_file *xef;
	struct xe_device *xe = d->xe;
	long ret = 0;

	if (XE_IOCTL_DBG(xe, !(_IOC_DIR(cmd) & _IOC_WRITE)))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, !(_IOC_DIR(cmd) & _IOC_READ)))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, _IOC_SIZE(cmd) < sizeof(user_arg)))
		return -EINVAL;

	if (copy_from_user(&user_arg, u64_to_user_ptr(arg), sizeof(user_arg)))
		return -EFAULT;

	if (XE_IOCTL_DBG(xe, user_arg.flags))
		return -EINVAL;

	if (!access_ok(u64_to_user_ptr(user_arg.ptr), user_arg.size))
		return -EFAULT;

	if (xe_eudebug_detached(d))
		return -ENOTCONN;

	eu_dbg(d,
	       "read metadata: client_handle=%llu, metadata_handle=%llu, flags=0x%x",
	       user_arg.client_handle, user_arg.metadata_handle, user_arg.flags);

	xef = find_client_get(d, user_arg.client_handle);
	if (XE_IOCTL_DBG(xe, !xef))
		return -EINVAL;

	mdata = find_metadata_get(d, (u32)user_arg.metadata_handle);
	if (XE_IOCTL_DBG(xe, !mdata)) {
		xe_file_put(xef);
		return -EINVAL;
	}

	if (user_arg.size) {
		if (user_arg.size < mdata->len) {
			ret = -EINVAL;
			goto metadata_put;
		}

		/* This limits us to a maximum payload size of 2G */
		if (copy_to_user(u64_to_user_ptr(user_arg.ptr),
				 mdata->ptr, mdata->len)) {
			ret = -EFAULT;
			goto metadata_put;
		}
	}

	user_arg.size = mdata->len;

	if (copy_to_user(u64_to_user_ptr(arg), &user_arg, sizeof(user_arg)))
		ret = -EFAULT;

metadata_put:
	prelim_xe_debug_metadata_put(mdata);
	xe_file_put(xef);
	return ret;
}

static long xe_eudebug_vm_open_ioctl(struct xe_eudebug *d, unsigned long arg);

static long xe_eudebug_ioctl(struct file *file,
			     unsigned int cmd,
			     unsigned long arg)
{
	struct xe_eudebug * const d = file->private_data;
	long ret;

	if (cmd != PRELIM_DRM_XE_EUDEBUG_IOCTL_READ_EVENT &&
	    !completion_done(&d->discovery))
		return -EBUSY;

	switch (cmd) {
	case PRELIM_DRM_XE_EUDEBUG_IOCTL_READ_EVENT:
		ret = xe_eudebug_read_event(d, arg,
					    !(file->f_flags & O_NONBLOCK));
		break;
	case PRELIM_DRM_XE_EUDEBUG_IOCTL_EU_CONTROL:
		ret = xe_eudebug_eu_control(d, arg);
		eu_dbg(d, "ioctl cmd=EU_CONTROL ret=%ld\n", ret);
		break;
	case PRELIM_DRM_XE_EUDEBUG_IOCTL_ACK_EVENT:
		ret = xe_eudebug_ack_event_ioctl(d, cmd, arg);
		eu_dbg(d, "ioctl cmd=EVENT_ACK ret=%ld\n", ret);
		break;
	case PRELIM_DRM_XE_EUDEBUG_IOCTL_VM_OPEN:
		ret = xe_eudebug_vm_open_ioctl(d, arg);
		eu_dbg(d, "ioctl cmd=VM_OPEN ret=%ld\n", ret);
		break;
	case PRELIM_DRM_XE_EUDEBUG_IOCTL_READ_METADATA:
		ret = xe_eudebug_read_metadata(d, cmd, arg);
		eu_dbg(d, "ioctl cmd=READ_METADATA ret=%ld\n", ret);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations fops = {
	.owner		= THIS_MODULE,
	.release	= xe_eudebug_release,
	.poll		= xe_eudebug_poll,
	.read		= xe_eudebug_read,
	.unlocked_ioctl	= xe_eudebug_ioctl,
};

static int __current_lrca(struct xe_hw_engine *hwe, u32 *lrc_hw)
{
	u32 lrc_reg;

	lrc_reg = xe_hw_engine_mmio_read32(hwe, RING_CURRENT_LRCA(0));

	if (!(lrc_reg & CURRENT_LRCA_VALID))
		return -ENOENT;

	*lrc_hw = lrc_reg & GENMASK(31, 12);

	return 0;
}

static int current_lrca(struct xe_hw_engine *hwe, u32 *lrc_hw)
{
	unsigned int fw_ref;
	int ret;

	fw_ref = xe_force_wake_get(gt_to_fw(hwe->gt), hwe->domain);
	if (!fw_ref)
		return -ETIMEDOUT;

	ret = __current_lrca(hwe, lrc_hw);

	xe_force_wake_put(gt_to_fw(hwe->gt), fw_ref);

	return ret;
}

static bool lrca_equals(u32 a, u32 b)
{
	return (a & GENMASK(31, 12)) == (b & GENMASK(31, 12));
}

static int match_exec_queue_lrca(struct xe_exec_queue *q, u32 lrc_hw)
{
	int i;

	for (i = 0; i < q->width; i++)
		if (lrca_equals(lower_32_bits(xe_lrc_descriptor(q->lrc[i])), lrc_hw))
			return i;

	return -1;
}

static int rcu_debug1_engine_index(const struct xe_hw_engine * const hwe)
{
	if (hwe->class == XE_ENGINE_CLASS_RENDER) {
		XE_WARN_ON(hwe->instance);
		return 0;
	}

	XE_WARN_ON(hwe->instance > 3);

	return hwe->instance + 1;
}

static u32 engine_status_xe1(const struct xe_hw_engine * const hwe,
			     u32 rcu_debug1)
{
	const unsigned int first = 7;
	const unsigned int incr = 3;
	const unsigned int i = rcu_debug1_engine_index(hwe);
	const unsigned int shift = first + (i * incr);

	return (rcu_debug1 >> shift) & RCU_DEBUG_1_ENGINE_STATUS;
}

static u32 engine_status_xe2(const struct xe_hw_engine * const hwe,
			     u32 rcu_debug1)
{
	const unsigned int first = 7;
	const unsigned int incr = 4;
	const unsigned int i = rcu_debug1_engine_index(hwe);
	const unsigned int shift = first + (i * incr);

	return (rcu_debug1 >> shift) & RCU_DEBUG_1_ENGINE_STATUS;
}

static u32 engine_status(const struct xe_hw_engine * const hwe,
			 u32 rcu_debug1)
{
	u32 status = 0;

	if (GRAPHICS_VER(gt_to_xe(hwe->gt)) < 20)
		status = engine_status_xe1(hwe, rcu_debug1);
	else if (GRAPHICS_VER(gt_to_xe(hwe->gt)) < 30)
		status = engine_status_xe2(hwe, rcu_debug1);
	else
		XE_WARN_ON(GRAPHICS_VER(gt_to_xe(hwe->gt)));

	return status;
}

static bool engine_is_runalone_set(const struct xe_hw_engine * const hwe,
				   u32 rcu_debug1)
{
	return engine_status(hwe, rcu_debug1) & RCU_DEBUG_1_RUNALONE_ACTIVE;
}

static bool engine_is_context_set(const struct xe_hw_engine * const hwe,
				  u32 rcu_debug1)
{
	return engine_status(hwe, rcu_debug1) & RCU_DEBUG_1_CONTEXT_ACTIVE;
}

static bool engine_has_runalone(const struct xe_hw_engine * const hwe)
{
	return hwe->class == XE_ENGINE_CLASS_RENDER ||
		hwe->class == XE_ENGINE_CLASS_COMPUTE;
}

static struct xe_hw_engine *get_runalone_active_hw_engine(struct xe_gt *gt)
{
	struct xe_hw_engine *hwe, *first = NULL;
	unsigned int num_active, id, fw_ref;
	u32 val;

	fw_ref = xe_force_wake_get(gt_to_fw(gt), XE_FW_GT);
	if (!fw_ref) {
		drm_dbg(&gt_to_xe(gt)->drm, "eudbg: runalone failed to get force wake\n");
		return NULL;
	}

	val = xe_mmio_read32(&gt->mmio, RCU_DEBUG_1);
	xe_force_wake_put(gt_to_fw(gt), fw_ref);

	drm_dbg(&gt_to_xe(gt)->drm, "eudbg: runalone RCU_DEBUG_1 = 0x%08x\n", val);

	num_active = 0;
	for_each_hw_engine(hwe, gt, id) {
		bool runalone, ctx;

		if (!engine_has_runalone(hwe))
			continue;

		runalone = engine_is_runalone_set(hwe, val);
		ctx = engine_is_context_set(hwe, val);

		drm_dbg(&gt_to_xe(gt)->drm, "eudbg: engine %s: runalone=%s, context=%s",
			hwe->name, runalone ? "active" : "inactive",
			ctx ? "active" : "inactive");

		/*
		 * On earlier gen12 the context status seems to be idle when
		 * it has raised attention. We have to omit the active bit.
		 */
		if (IS_DGFX(gt_to_xe(gt)))
			ctx = true;

		if (runalone && ctx) {
			num_active++;

			drm_dbg(&gt_to_xe(gt)->drm, "eudbg: runalone engine %s %s",
				hwe->name, first ? "selected" : "found");
			if (!first)
				first = hwe;
		}
	}

	if (num_active > 1)
		drm_err(&gt_to_xe(gt)->drm, "eudbg: %d runalone engines active!",
			num_active);

	return first;
}

static struct xe_exec_queue *active_hwe_to_exec_queue(struct xe_hw_engine *hwe, int *lrc_idx)
{
	struct xe_device *xe = gt_to_xe(hwe->gt);
	struct xe_gt *gt = hwe->gt;
	struct xe_exec_queue *q, *found = NULL;
	struct xe_file *xef;
	unsigned long i;
	int idx, err;
	u32 lrc_hw;

	err = current_lrca(hwe, &lrc_hw);
	if (err)
		return ERR_PTR(err);

	/* Take write so that we can safely check the lists */
	down_write(&xe->eudebug.discovery_lock);
	list_for_each_entry(xef, &xe->clients.list, eudebug.client_link) {
		xa_for_each(&xef->exec_queue.xa, i, q) {
			if (q->gt != gt)
				continue;

			if (q->class != hwe->class)
				continue;

			if (xe_exec_queue_is_idle(q))
				continue;

			idx = match_exec_queue_lrca(q, lrc_hw);
			if (idx < 0)
				continue;

			found = xe_exec_queue_get(q);

			if (lrc_idx)
				*lrc_idx = idx;

			break;
		}

		if (found)
			break;
	}
	up_write(&xe->eudebug.discovery_lock);

	if (!found)
		return ERR_PTR(-ENOENT);

	if (XE_WARN_ON(current_lrca(hwe, &lrc_hw)) &&
	    XE_WARN_ON(match_exec_queue_lrca(found, lrc_hw) < 0)) {
		xe_exec_queue_put(found);
		return ERR_PTR(-ENOENT);
	}

	return found;
}

static struct xe_exec_queue *runalone_active_queue_get(struct xe_gt *gt, int *lrc_idx)
{
	struct xe_hw_engine *active;

	active = get_runalone_active_hw_engine(gt);
	if (!active) {
		drm_dbg(&gt_to_xe(gt)->drm, "Runalone engine not found!");
		return ERR_PTR(-ENOENT);
	}

	return active_hwe_to_exec_queue(active, lrc_idx);
}

static int send_attention_event(struct xe_eudebug *d, struct xe_exec_queue *q, int lrc_idx)
{
	struct xe_eudebug_event_eu_attention *ea;
	struct xe_eudebug_event *event;
	int h_c, h_queue, h_lrc;
	u32 size = prelim_xe_gt_eu_attention_bitmap_size(q->gt);
	u32 sz = struct_size(ea, bitmask, size);
	int ret;

	XE_WARN_ON(lrc_idx < 0 || lrc_idx >= q->width);

	XE_WARN_ON(!xe_exec_queue_is_debuggable(q));

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, q->vm->xef);
	if (h_c < 0)
		return h_c;

	h_queue = find_handle(d->res, XE_EUDEBUG_RES_TYPE_EXEC_QUEUE, q);
	if (h_queue < 0)
		return h_queue;

	h_lrc = find_handle(d->res, XE_EUDEBUG_RES_TYPE_LRC, q->lrc[lrc_idx]);
	if (h_lrc < 0)
		return h_lrc;

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_EU_ATTENTION, 0,
					PRELIM_DRM_XE_EUDEBUG_EVENT_STATE_CHANGE, sz);

	if (!event)
		return -ENOSPC;

	ea = cast_event(ea, event);
	write_member(struct prelim_drm_xe_eudebug_event_eu_attention, ea, client_handle, (u64)h_c);
	write_member(struct prelim_drm_xe_eudebug_event_eu_attention, ea, exec_queue_handle, (u64)h_queue);
	write_member(struct prelim_drm_xe_eudebug_event_eu_attention, ea, lrc_handle, (u64)h_lrc);
	write_member(struct prelim_drm_xe_eudebug_event_eu_attention, ea, bitmask_size, size);

	mutex_lock(&d->eu_lock);
	event->seqno = atomic_long_inc_return(&d->events.seqno);
	ret = prelim_xe_gt_eu_attention_bitmap(q->gt, &ea->bitmask[0], ea->bitmask_size);
	mutex_unlock(&d->eu_lock);

	if (ret)
		return ret;

	return xe_eudebug_queue_event(d, event);
}

static int xe_send_gt_attention(struct xe_gt *gt)
{
	struct xe_eudebug *d;
	struct xe_exec_queue *q;
	int ret, lrc_idx;

	if (list_empty_careful(&gt_to_xe(gt)->eudebug.list))
		return -ENOTCONN;

	q = runalone_active_queue_get(gt, &lrc_idx);
	if (IS_ERR(q))
		return PTR_ERR(q);

	if (!xe_exec_queue_is_debuggable(q)) {
		ret = -EPERM;
		goto err_exec_queue_put;
	}

	d = _xe_eudebug_get(q->vm->xef);
	if (!d) {
		ret = -ENOTCONN;
		goto err_exec_queue_put;
	}

	if (!completion_done(&d->discovery)) {
		eu_dbg(d, "discovery not yet done\n");
		ret = -EBUSY;
		goto err_eudebug_put;
	}

	ret = send_attention_event(d, q, lrc_idx);
	if (ret)
		xe_eudebug_disconnect(d, ret);

err_eudebug_put:
	prelim_xe_eudebug_put(d);
err_exec_queue_put:
	xe_exec_queue_put(q);

	return ret;
}

static int xe_eudebug_handle_gt_attention(struct xe_gt *gt)
{
	int ret;

	ret = prelim_xe_gt_eu_threads_needing_attention(gt);
	if (ret <= 0)
		return ret;

	ret = xe_send_gt_attention(gt);

	/* Discovery in progress, fake it */
	if (ret == -EBUSY)
		return 0;

	return ret;
}

static int send_pagefault_event(struct xe_eudebug *d, struct xe_eudebug_pagefault *pf)
{
	struct xe_eudebug_event_pagefault *ep;
	struct xe_eudebug_event *event;
	int h_c, h_queue, h_lrc;
	u32 size = prelim_xe_gt_eu_attention_bitmap_size(pf->q->gt) * 3;
	u32 sz = struct_size(ep, bitmask, size);

	XE_WARN_ON(pf->lrc_idx < 0 || pf->lrc_idx >= pf->q->width);

	XE_WARN_ON(!xe_exec_queue_is_debuggable(pf->q));

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, pf->q->vm->xef);
	if (h_c < 0)
		return h_c;

	h_queue = find_handle(d->res, XE_EUDEBUG_RES_TYPE_EXEC_QUEUE, pf->q);
	if (h_queue < 0)
		return h_queue;

	h_lrc = find_handle(d->res, XE_EUDEBUG_RES_TYPE_LRC, pf->q->lrc[pf->lrc_idx]);
	if (h_lrc < 0)
		return h_lrc;

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_PAGEFAULT, 0,
					PRELIM_DRM_XE_EUDEBUG_EVENT_STATE_CHANGE, sz);

	if (!event)
		return -ENOSPC;

	ep = cast_event(ep, event);
	write_member(struct xe_eudebug_event_pagefault, ep, client_handle, (u64)h_c);
	write_member(struct xe_eudebug_event_pagefault, ep, exec_queue_handle, (u64)h_queue);
	write_member(struct xe_eudebug_event_pagefault, ep, lrc_handle, (u64)h_lrc);
	write_member(struct xe_eudebug_event_pagefault, ep, bitmask_size, size);
	write_member(struct xe_eudebug_event_pagefault, ep, pagefault_address, pf->fault.addr);

	memcpy(ep->bitmask, pf->attentions.before.att, pf->attentions.before.size);
	memcpy(ep->bitmask + pf->attentions.before.size,
	       pf->attentions.after.att, pf->attentions.after.size);
	memcpy(ep->bitmask + pf->attentions.before.size + pf->attentions.after.size,
	       pf->attentions.resolved.att, pf->attentions.resolved.size);

	event->seqno = atomic_long_inc_return(&d->events.seqno);

	return xe_eudebug_queue_event(d, event);
}

static int send_pagefault(struct xe_gt *gt, struct xe_eudebug_pagefault *pf,
			  bool from_attention_scan)
{
	struct xe_eudebug *d;
	struct xe_exec_queue *q;
	int ret, lrc_idx;

	if (list_empty_careful(&gt_to_xe(gt)->eudebug.list))
		return -ENOTCONN;

	q = runalone_active_queue_get(gt, &lrc_idx);
	if (IS_ERR(q))
		return PTR_ERR(q);

	if (!xe_exec_queue_is_debuggable(q)) {
		ret = -EPERM;
		goto out_exec_queue_put;
	}

	d = _xe_eudebug_get(q->vm->xef);
	if (!d) {
		ret = -ENOTCONN;
		goto out_exec_queue_put;
	}

	if (!completion_done(&d->discovery)) {
		eu_dbg(d, "discovery not yet done\n");
		ret = -EBUSY;
		goto out_eudebug_put;
	}

	if (pf->deferred_resolved) {
		prelim_xe_gt_eu_attentions_read(gt, &pf->attentions.resolved,
					 PRELIM_XE_GT_ATTENTION_TIMEOUT_MS);

		if (!xe_eu_attentions_xor_count(&pf->attentions.after,
						&pf->attentions.resolved) &&
		    !from_attention_scan) {
			eu_dbg(d, "xe attentions not yet updated\n");
			ret = -EBUSY;
			goto out_eudebug_put;
		}
	}

	ret = send_pagefault_event(d, pf);
	if (ret)
		xe_eudebug_disconnect(d, ret);

out_eudebug_put:
	prelim_xe_eudebug_put(d);
out_exec_queue_put:
	xe_exec_queue_put(q);

	return ret;
}

static int send_queued_pagefault(struct xe_eudebug *d, bool from_attention_scan)
{
	struct xe_eudebug_pagefault *pf, *pf_temp;
	int ret = 0;

	mutex_lock(&d->pf_lock);
	list_for_each_entry_safe(pf, pf_temp, &d->pagefaults, list) {
		struct xe_gt *gt =pf->q->gt;

		ret = send_pagefault(gt, pf, from_attention_scan);

		/* if resolved attentions are not updated */
		if (ret == -EBUSY)
			break;

		/* decrease the reference count of xe_exec_queue obtained from pagefault handler */
		xe_exec_queue_put(pf->q);
		list_del(&pf->list);
		kfree(pf);

		if (ret)
			break;
	}
	mutex_unlock(&d->pf_lock);

	return ret;
}

static int handle_gt_queued_pagefault(struct xe_gt *gt)
{
	struct xe_exec_queue *q;
	struct xe_eudebug *d;
	int ret, lrc_idx;

	ret = prelim_xe_gt_eu_threads_needing_attention(gt);
	if (ret <= 0)
		return ret;

	if (list_empty_careful(&gt_to_xe(gt)->eudebug.list))
		return -ENOTCONN;

	q = runalone_active_queue_get(gt, &lrc_idx);
	if (IS_ERR(q))
		return PTR_ERR(q);

	if (!xe_exec_queue_is_debuggable(q)) {
		ret = -EPERM;
		goto out_exec_queue_put;
	}

	d = _xe_eudebug_get(q->vm->xef);
	if (!d) {
		ret = -ENOTCONN;
		goto out_exec_queue_put;
	}

	if (!completion_done(&d->discovery)) {
		eu_dbg(d, "discovery not yet done\n");
		ret = -EBUSY;
		goto out_eudebug_put;
	}

	ret = send_queued_pagefault(d, true);

out_eudebug_put:
	prelim_xe_eudebug_put(d);
out_exec_queue_put:
	xe_exec_queue_put(q);

	return ret;
}

#define XE_EUDEBUG_ATTENTION_INTERVAL 100
static void attention_scan_fn(struct work_struct *work)
{
	struct xe_device *xe = container_of(work, typeof(*xe), eudebug.attention_scan.work);
	long delay = msecs_to_jiffies(XE_EUDEBUG_ATTENTION_INTERVAL);
	struct xe_gt *gt;
	u8 gt_id;

	if (list_empty_careful(&xe->eudebug.list))
		delay *= 10;

	if (delay >= HZ)
		delay = round_jiffies_up_relative(delay);

	if (xe_pm_runtime_get_if_active(xe)) {
		for_each_gt(gt, xe, gt_id) {
			int ret;

			if (gt->info.type != XE_GT_TYPE_MAIN)
				continue;

			handle_gt_queued_pagefault(gt);

			ret = xe_eudebug_handle_gt_attention(gt);
			if (ret) {
				// TODO: error capture
				drm_info(&gt_to_xe(gt)->drm,
					 "gt:%d unable to handle eu attention ret=%d\n",
					 gt_id, ret);

				xe_gt_reset_async(gt);
			}
		}

		xe_pm_runtime_put(xe);
	}

	schedule_delayed_work(&xe->eudebug.attention_scan, delay);
}

static void attention_scan_cancel(struct xe_device *xe)
{
	cancel_delayed_work_sync(&xe->eudebug.attention_scan);
}

static void attention_scan_flush(struct xe_device *xe)
{
	mod_delayed_work(system_wq, &xe->eudebug.attention_scan, 0);
}

static int xe_eu_control_interrupt_all(struct xe_eudebug *d,
				       struct xe_exec_queue *q,
				       struct xe_lrc *lrc)
{
	struct xe_gt *gt = q->hwe->gt;
	struct xe_device *xe = d->xe;
	struct xe_exec_queue *active;
	struct xe_hw_engine *hwe;
	unsigned int fw_ref;
	int lrc_idx, ret;
	u32 lrc_hw;
	u32 td_ctl;

	hwe = get_runalone_active_hw_engine(gt);
	if (XE_IOCTL_DBG(xe, !hwe)) {
		drm_dbg(&gt_to_xe(gt)->drm, "Runalone engine not found!");
		return -EINVAL;
	}

	active = active_hwe_to_exec_queue(hwe, &lrc_idx);
	if (XE_IOCTL_DBG(xe, IS_ERR(active)))
		return PTR_ERR(active);

	if (XE_IOCTL_DBG(xe, q != active)) {
		xe_exec_queue_put(active);
		return -EINVAL;
	}
	xe_exec_queue_put(active);

	if (XE_IOCTL_DBG(xe, lrc_idx >= q->width || q->lrc[lrc_idx] != lrc))
		return -EINVAL;

	fw_ref = xe_force_wake_get(gt_to_fw(gt), hwe->domain);
	if (!fw_ref)
		return -ETIMEDOUT;

	/* Additional check just before issuing MMIO writes */
	ret = __current_lrca(hwe, &lrc_hw);
	if (ret)
		goto put_fw;

	if (!lrca_equals(lower_32_bits(xe_lrc_descriptor(lrc)), lrc_hw)) {
		ret = -EBUSY;
		goto put_fw;
	}

	td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);

	/* Halt on next thread dispatch */
	if (!(td_ctl & TD_CTL_FORCE_EXTERNAL_HALT))
		xe_gt_mcr_multicast_write(gt, TD_CTL,
					  td_ctl | TD_CTL_FORCE_EXTERNAL_HALT);
	else
		eu_warn(d, "TD_CTL force external halt bit already set!\n");

	/*
	 * The sleep is needed because some interrupts are ignored
	 * by the HW, hence we allow the HW some time to acknowledge
	 * that.
	 */
	usleep_range(100, 110);

	/* Halt regardless of thread dependencies */
	if (!(td_ctl & TD_CTL_FORCE_EXCEPTION))
		xe_gt_mcr_multicast_write(gt, TD_CTL,
					  td_ctl | TD_CTL_FORCE_EXCEPTION);
	else
		eu_warn(d, "TD_CTL force exception bit already set!\n");

	usleep_range(100, 110);

	xe_gt_mcr_multicast_write(gt, TD_CTL, td_ctl &
				  ~(TD_CTL_FORCE_EXTERNAL_HALT | TD_CTL_FORCE_EXCEPTION));

	/*
	 * In case of stopping wrong ctx emit warning.
	 * Nothing else we can do for now.
	 */
	ret = __current_lrca(hwe, &lrc_hw);
	if (ret || !lrca_equals(lower_32_bits(xe_lrc_descriptor(lrc)), lrc_hw))
		eu_warn(d, "xe_eudebug: interrupted wrong context.");

put_fw:
	xe_force_wake_put(gt_to_fw(gt), fw_ref);

	return ret;
}

struct ss_iter {
	struct xe_eudebug *debugger;
	unsigned int i;

	unsigned int size;
	u8 *bits;
};

static int check_attn_mcr(struct xe_gt *gt, void *data,
			  u16 group, u16 instance)
{
	struct ss_iter *iter = data;
	struct xe_eudebug *d = iter->debugger;
	unsigned int row;

	for (row = 0; row < PRELIM_TD_EU_ATTENTION_MAX_ROWS; row++) {
		u32 val, cur = 0;

		if (iter->i >= iter->size)
			return 0;

		if (XE_WARN_ON((iter->i + sizeof(val)) >
				(prelim_xe_gt_eu_attention_bitmap_size(gt))))
			return -EIO;

		memcpy(&val, &iter->bits[iter->i], sizeof(val));
		iter->i += sizeof(val);

		cur = xe_gt_mcr_unicast_read(gt, TD_ATT(row), group, instance);

		if ((val | cur) != cur) {
			eu_dbg(d,
			       "WRONG CLEAR (%u:%u:%u) TD_CRL: 0x%08x; TD_ATT: 0x%08x\n",
			       group, instance, row, val, cur);
			return -EINVAL;
		}
	}

	return 0;
}

static int clear_attn_mcr(struct xe_gt *gt, void *data,
			  u16 group, u16 instance)
{
	struct ss_iter *iter = data;
	struct xe_eudebug *d = iter->debugger;
	unsigned int row;

	for (row = 0; row < PRELIM_TD_EU_ATTENTION_MAX_ROWS; row++) {
		u32 val;

		if (iter->i >= iter->size)
			return 0;

		if (XE_WARN_ON((iter->i + sizeof(val)) >
				(prelim_xe_gt_eu_attention_bitmap_size(gt))))
			return -EIO;

		memcpy(&val, &iter->bits[iter->i], sizeof(val));
		iter->i += sizeof(val);

		if (!val)
			continue;

		xe_gt_mcr_unicast_write(gt, TD_CLR(row), val,
					group, instance);

		eu_dbg(d,
		       "TD_CLR: (%u:%u:%u): 0x%08x\n",
		       group, instance, row, val);
	}

	return 0;
}

static int xe_eu_control_resume(struct xe_eudebug *d,
				struct xe_exec_queue *q,
				struct xe_lrc *lrc,
				u8 *bits, unsigned int bitmask_size)
{
	struct xe_device *xe = d->xe;
	struct ss_iter iter = {
		.debugger = d,
		.i = 0,
		.size = bitmask_size,
		.bits = bits
	};
	int ret = 0;
	struct xe_exec_queue *active;
	int lrc_idx;

	active = runalone_active_queue_get(q->gt, &lrc_idx);
	if (IS_ERR(active))
		return PTR_ERR(active);

	if (XE_IOCTL_DBG(xe, q != active)) {
		xe_exec_queue_put(active);
		return -EBUSY;
	}
	xe_exec_queue_put(active);

	if (XE_IOCTL_DBG(xe, lrc_idx >= q->width || q->lrc[lrc_idx] != lrc))
		return -EBUSY;

	/*
	 * hsdes: 18021122357
	 * We need to avoid clearing attention bits that are not set
	 * in order to avoid the EOT hang on PVC.
	 */
	if (GRAPHICS_VERx100(d->xe) == 1260) {
		ret = prelim_xe_gt_foreach_dss_group_instance(q->gt, check_attn_mcr, &iter);
		if (ret)
			return ret;

		iter.i = 0;
	}

	prelim_xe_gt_foreach_dss_group_instance(q->gt, clear_attn_mcr, &iter);
	return 0;
}

static int xe_eu_control_stopped(struct xe_eudebug *d,
				 struct xe_exec_queue *q,
				 struct xe_lrc *lrc,
				 u8 *bits, unsigned int bitmask_size)
{
	struct xe_device *xe = d->xe;
	struct xe_exec_queue *active;
	int lrc_idx;

	if (XE_WARN_ON(!q) || XE_WARN_ON(!q->gt))
		return -EINVAL;

	active = runalone_active_queue_get(q->gt, &lrc_idx);
	if (IS_ERR(active))
		return PTR_ERR(active);

	if (active) {
		if (XE_IOCTL_DBG(xe, q != active)) {
			xe_exec_queue_put(active);
			return -EBUSY;
		}

		if (XE_IOCTL_DBG(xe, lrc_idx >= q->width || q->lrc[lrc_idx] != lrc)) {
			xe_exec_queue_put(active);
			return -EBUSY;
		}
	}

	xe_exec_queue_put(active);

	return prelim_xe_gt_eu_attention_bitmap(q->gt, bits, bitmask_size);
}

static struct xe_eudebug_eu_control_ops eu_control = {
	.interrupt_all = xe_eu_control_interrupt_all,
	.stopped = xe_eu_control_stopped,
	.resume = xe_eu_control_resume,
};

static void discovery_work_fn(struct work_struct *work);

static int
xe_eudebug_connect(struct xe_device *xe,
		   struct prelim_drm_xe_eudebug_connect *param)
{
	const u64 known_open_flags = 0;
	unsigned long f_flags = 0;
	struct xe_eudebug *d;
	int fd, err;

	if (param->extensions)
		return -EINVAL;

	if (!param->pid)
		return -EINVAL;

	if (param->flags & ~known_open_flags)
		return -EINVAL;

	if (param->version && param->version != PRELIM_DRM_XE_EUDEBUG_VERSION)
		return -EINVAL;

	param->version = PRELIM_DRM_XE_EUDEBUG_VERSION;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	kref_init(&d->ref);
	spin_lock_init(&d->connection.lock);
	mutex_init(&d->eu_lock);
	mutex_init(&d->pf_lock);
	INIT_LIST_HEAD(&d->pagefaults);
	init_waitqueue_head(&d->events.write_done);
	init_waitqueue_head(&d->events.read_done);
	init_completion(&d->discovery);

	spin_lock_init(&d->events.lock);
	INIT_KFIFO(d->events.fifo);
	INIT_WORK(&d->discovery_work, discovery_work_fn);

	spin_lock_init(&d->acks.lock);
	d->acks.tree = RB_ROOT;

	d->res = xe_eudebug_resources_alloc();
	if (IS_ERR(d->res)) {
		err = PTR_ERR(d->res);
		goto err_free;
	}

	err = xe_eudebug_attach(xe, d, param->pid);
	if (err)
		goto err_free_res;

	fd = anon_inode_getfd("[xe_eudebug]", &fops, d, f_flags);
	if (fd < 0) {
		err = fd;
		goto err_detach;
	}

	d->ops = &eu_control;
	kref_get(&d->ref);
	queue_work(xe->eudebug.ordered_wq, &d->discovery_work);
	attention_scan_flush(xe);

	eu_dbg(d, "connected session %lld", d->session);

	return fd;

err_detach:
	xe_eudebug_detach(xe, d, err);
err_free_res:
	xe_eudebug_destroy_resources(d);
err_free:
	kfree(d);

	return err;
}

int prelim_xe_eudebug_connect_ioctl(struct drm_device *dev,
			     void *data,
			     struct drm_file *file)
{
	struct xe_device *xe = to_xe_device(dev);
	struct prelim_drm_xe_eudebug_connect * const param = data;

	lockdep_assert_held(&xe->eudebug.discovery_lock);

	if (!xe->eudebug.enable)
		return -ENODEV;

	return xe_eudebug_connect(xe, param);
}

static void add_sr_entry(struct xe_hw_engine *hwe,
			 struct xe_reg_mcr mcr_reg,
			 u32 mask, bool enable)
{
	const struct xe_reg_sr_entry sr_entry = {
		.reg = mcr_reg.__reg,
		.clr_bits = mask,
		.set_bits = enable ? mask : 0,
		.read_mask = mask,
	};

	xe_reg_sr_add(&hwe->reg_sr, &sr_entry, hwe->gt, true);
}

static void xe_eudebug_reinit_hw_engine(struct xe_hw_engine *hwe, bool enable)
{
	struct xe_gt *gt = hwe->gt;
	struct xe_device *xe = gt_to_xe(gt);

	if (!xe->eudebug.available)
		return;

	if (!xe_rtp_match_first_render_or_compute(gt, hwe))
		return;

	if (XE_WA(gt, 18022722726))
		add_sr_entry(hwe, ROW_CHICKEN,
			     STALL_DOP_GATING_DISABLE, enable);

	if (XE_WA(gt, 14015474168))
		add_sr_entry(hwe, ROW_CHICKEN2,
			     XEHPC_DISABLE_BTB,
			     enable);

	if (xe->info.graphics_verx100 >= 1200)
		add_sr_entry(hwe, TD_CTL,
			     TD_CTL_BREAKPOINT_ENABLE |
			     TD_CTL_FORCE_THREAD_BREAKPOINT_ENABLE |
			     TD_CTL_FEH_AND_FEE_ENABLE,
			     enable);

	if (xe->info.graphics_verx100 >= 1250)
		add_sr_entry(hwe, TD_CTL,
			     TD_CTL_GLOBAL_DEBUG_ENABLE, enable);
}

static int xe_eudebug_enable(struct xe_device *xe, bool enable)
{
	struct xe_gt *gt;
	int i;
	u8 id;

	if (!xe->eudebug.available)
		return -EOPNOTSUPP;

	/*
	 * The connect ioctl has read lock so we can
	 * serialize with taking write
	 */
	down_write(&xe->eudebug.discovery_lock);

	if (!enable && !list_empty(&xe->eudebug.list)) {
		up_write(&xe->eudebug.discovery_lock);
		return -EBUSY;
	}

	if (enable == xe->eudebug.enable) {
		up_write(&xe->eudebug.discovery_lock);
		return 0;
	}

	for_each_gt(gt, xe, id) {
		for (i = 0; i < ARRAY_SIZE(gt->hw_engines); i++) {
			if (!(gt->info.engine_mask & BIT(i)))
				continue;

			xe_eudebug_reinit_hw_engine(&gt->hw_engines[i], enable);
		}

		xe_gt_reset_async(gt);
		flush_work(&gt->reset.worker);
	}

	xe->eudebug.enable = enable;
	up_write(&xe->eudebug.discovery_lock);

	if (enable)
		attention_scan_flush(xe);
	else
		attention_scan_cancel(xe);

	return 0;
}

static ssize_t prelim_enable_eudebug_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct xe_device *xe = pdev_to_xe_device(to_pci_dev(dev));

	return sysfs_emit(buf, "%u\n", xe->eudebug.enable);
}

static ssize_t prelim_enable_eudebug_store(struct device *dev, struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct xe_device *xe = pdev_to_xe_device(to_pci_dev(dev));
	bool enable;
	int ret;

	ret = kstrtobool(buf, &enable);
	if (ret)
		return ret;

	ret = xe_eudebug_enable(xe, enable);
	if (ret)
		return ret;

	return count;
}

static DEVICE_ATTR_RW(prelim_enable_eudebug);

static void xe_eudebug_sysfs_fini(void *arg)
{
	struct xe_device *xe = arg;

	sysfs_remove_file(&xe->drm.dev->kobj, &dev_attr_prelim_enable_eudebug.attr);
}

void prelim_xe_eudebug_init(struct xe_device *xe)
{
	struct device *dev = xe->drm.dev;
	int ret;

	spin_lock_init(&xe->eudebug.lock);
	INIT_LIST_HEAD(&xe->eudebug.list);

	spin_lock_init(&xe->clients.lock);
	INIT_LIST_HEAD(&xe->clients.list);
	init_rwsem(&xe->eudebug.discovery_lock);
	INIT_DELAYED_WORK(&xe->eudebug.attention_scan, attention_scan_fn);

	xe->eudebug.ordered_wq = alloc_ordered_workqueue("xe-eudebug-ordered-wq", 0);
	xe->eudebug.available = !!xe->eudebug.ordered_wq;

	if (!xe->eudebug.available)
		return;

	ret = sysfs_create_file(&xe->drm.dev->kobj, &dev_attr_prelim_enable_eudebug.attr);
	if (ret)
		drm_warn(&xe->drm, "eudebug sysfs init failed: %d, debugger unavailable\n", ret);
	else
		devm_add_action_or_reset(dev, xe_eudebug_sysfs_fini, xe);

	xe->eudebug.available = ret == 0;
}

void prelim_xe_eudebug_fini(struct xe_device *xe)
{
	attention_scan_cancel(xe);
	xe_assert(xe, list_empty_careful(&xe->eudebug.list));

	if (xe->eudebug.ordered_wq)
		destroy_workqueue(xe->eudebug.ordered_wq);
}

static int send_open_event(struct xe_eudebug *d, u32 flags, const u64 handle,
			   const u64 seqno)
{
	struct xe_eudebug_event *event;
	struct xe_eudebug_event_open *eo;

	if (!handle)
		return -EINVAL;

	if (XE_WARN_ON((long)handle >= INT_MAX))
		return -EINVAL;

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_OPEN, seqno,
					flags, sizeof(*eo));
	if (!event)
		return -ENOMEM;

	eo = cast_event(eo, event);

	write_member(struct prelim_drm_xe_eudebug_event_client, eo,
		     client_handle, handle);

	return xe_eudebug_queue_event(d, event);
}

static int client_create_event(struct xe_eudebug *d, struct xe_file *xef)
{
	u64 seqno;
	int ret;

	ret = xe_eudebug_add_handle(d, XE_EUDEBUG_RES_TYPE_CLIENT, xef, &seqno);
	if (ret > 0)
		ret = send_open_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE,
				      ret, seqno);

	return ret;
}

static int client_destroy_event(struct xe_eudebug *d, struct xe_file *xef)
{
	u64 seqno;
	int ret;

	ret = xe_eudebug_remove_handle(d, XE_EUDEBUG_RES_TYPE_CLIENT,
				       xef, &seqno);
	if (ret > 0)
		ret = send_open_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_DESTROY,
				      ret, seqno);

	return ret;
}

#define xe_eudebug_event_put(_d, _err) ({ \
	if ((_err)) \
		xe_eudebug_disconnect((_d), (_err)); \
	prelim_xe_eudebug_put((_d)); \
	})

void prelim_xe_eudebug_file_open(struct xe_file *xef)
{
	struct xe_eudebug *d;

	INIT_LIST_HEAD(&xef->eudebug.client_link);
	mutex_init(&xef->eudebug.metadata.lock);
	xa_init_flags(&xef->eudebug.metadata.xa, XA_FLAGS_ALLOC1);

	down_read(&xef->xe->eudebug.discovery_lock);

	spin_lock(&xef->xe->clients.lock);
	list_add_tail(&xef->eudebug.client_link, &xef->xe->clients.list);
	spin_unlock(&xef->xe->clients.lock);

	d = prelim_xe_eudebug_get(xef);
	if (d)
		xe_eudebug_event_put(d, client_create_event(d, xef));

	up_read(&xef->xe->eudebug.discovery_lock);
}

void prelim_xe_eudebug_file_close(struct xe_file *xef)
{
	struct xe_eudebug *d;
	unsigned long idx;
	struct prelim_xe_debug_metadata *mdata;

	down_read(&xef->xe->eudebug.discovery_lock);
	d = prelim_xe_eudebug_get(xef);
	if (d)
		xe_eudebug_event_put(d, client_destroy_event(d, xef));

	mutex_lock(&xef->eudebug.metadata.lock);
	xa_for_each(&xef->eudebug.metadata.xa, idx, mdata)
		prelim_xe_debug_metadata_put(mdata);
	mutex_unlock(&xef->eudebug.metadata.lock);

	xa_destroy(&xef->eudebug.metadata.xa);
	mutex_destroy(&xef->eudebug.metadata.lock);

	spin_lock(&xef->xe->clients.lock);
	list_del_init(&xef->eudebug.client_link);
	spin_unlock(&xef->xe->clients.lock);

	up_read(&xef->xe->eudebug.discovery_lock);
}

static int send_vm_event(struct xe_eudebug *d, u32 flags,
			 const u64 client_handle,
			 const u64 vm_handle,
			 const u64 seqno)
{
	struct xe_eudebug_event *event;
	struct xe_eudebug_event_vm *e;

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_VM,
					seqno, flags, sizeof(*e));
	if (!event)
		return -ENOMEM;

	e = cast_event(e, event);

	write_member(struct prelim_drm_xe_eudebug_event_vm, e, client_handle, client_handle);
	write_member(struct prelim_drm_xe_eudebug_event_vm, e, vm_handle, vm_handle);

	return xe_eudebug_queue_event(d, event);
}

static int vm_create_event(struct xe_eudebug *d,
			   struct xe_file *xef, struct xe_vm *vm)
{
	int h_c, h_vm;
	u64 seqno;
	int ret;

	if (!xe_vm_in_lr_mode(vm))
		return 0;

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, xef);
	if (h_c < 0)
		return h_c;

	xe_eudebug_assert(d, h_c);

	h_vm = xe_eudebug_add_handle(d, XE_EUDEBUG_RES_TYPE_VM, vm, &seqno);
	if (h_vm <= 0)
		return h_vm;

	ret = send_vm_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE, h_c, h_vm, seqno);

	return ret;
}

static int vm_destroy_event(struct xe_eudebug *d,
			    struct xe_file *xef, struct xe_vm *vm)
{
	int h_c, h_vm;
	u64 seqno;

	if (!xe_vm_in_lr_mode(vm))
		return 0;

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, xef);
	if (h_c < 0) {
		XE_WARN_ON("no client found for vm");
		eu_warn(d, "no client found for vm");
		return h_c;
	}

	xe_eudebug_assert(d, h_c);

	h_vm = xe_eudebug_remove_handle(d, XE_EUDEBUG_RES_TYPE_VM, vm, &seqno);
	if (h_vm <= 0)
		return h_vm;

	return send_vm_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_DESTROY, h_c, h_vm, seqno);
}

void prelim_xe_eudebug_vm_create(struct xe_file *xef, struct xe_vm *vm)
{
	struct xe_eudebug *d;

	if (!xe_vm_in_lr_mode(vm))
		return;

	d = prelim_xe_eudebug_get(xef);
	if (!d)
		return;

	xe_eudebug_event_put(d, vm_create_event(d, xef, vm));
}

void prelim_xe_eudebug_vm_destroy(struct xe_file *xef, struct xe_vm *vm)
{
	struct xe_eudebug *d;

	if (!xe_vm_in_lr_mode(vm))
		return;

	d = prelim_xe_eudebug_get(xef);
	if (!d)
		return;

	xe_eudebug_event_put(d, vm_destroy_event(d, xef, vm));
}

static bool exec_queue_class_is_tracked(enum xe_engine_class class)
{
	return class == XE_ENGINE_CLASS_COMPUTE ||
		class == XE_ENGINE_CLASS_RENDER;
}

static const u16 xe_to_user_engine_class[] = {
	[XE_ENGINE_CLASS_RENDER] = DRM_XE_ENGINE_CLASS_RENDER,
	[XE_ENGINE_CLASS_COPY] = DRM_XE_ENGINE_CLASS_COPY,
	[XE_ENGINE_CLASS_VIDEO_DECODE] = DRM_XE_ENGINE_CLASS_VIDEO_DECODE,
	[XE_ENGINE_CLASS_VIDEO_ENHANCE] = DRM_XE_ENGINE_CLASS_VIDEO_ENHANCE,
	[XE_ENGINE_CLASS_COMPUTE] = DRM_XE_ENGINE_CLASS_COMPUTE,
};

static int send_exec_queue_event(struct xe_eudebug *d, u32 flags,
				 u64 client_handle, u64 vm_handle,
				 u64 exec_queue_handle, enum xe_engine_class class,
				 u32 width, u64 *lrc_handles, u64 seqno)
{
	struct xe_eudebug_event *event;
	struct xe_eudebug_event_exec_queue *e;
	const u32 sz = struct_size(e, lrc_handle, width);
	const u32 xe_engine_class = xe_to_user_engine_class[class];

	if (!exec_queue_class_is_tracked(class))
		return -EINVAL;

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_EXEC_QUEUE,
					seqno, flags, sz);
	if (!event)
		return -ENOMEM;

	e = cast_event(e, event);

	write_member(struct prelim_drm_xe_eudebug_event_exec_queue, e, client_handle, client_handle);
	write_member(struct prelim_drm_xe_eudebug_event_exec_queue, e, vm_handle, vm_handle);
	write_member(struct prelim_drm_xe_eudebug_event_exec_queue, e, exec_queue_handle,
		     exec_queue_handle);
	write_member(struct prelim_drm_xe_eudebug_event_exec_queue, e, engine_class, xe_engine_class);
	write_member(struct prelim_drm_xe_eudebug_event_exec_queue, e, width, width);

	memcpy(e->lrc_handle, lrc_handles, width);

	return xe_eudebug_queue_event(d, event);
}

static int send_exec_queue_placements_event(struct xe_eudebug *d,
					    u64 client_handle, u64 vm_handle,
					    u64 exec_queue_handle, u64 lrc_handle,
					    u32 num_placements, u64 *instances,
					    u64 seqno)
{
	struct xe_eudebug_event_exec_queue_placements *e;
	const u32 sz = struct_size(e, instances, num_placements);
	struct xe_eudebug_event *event;

	event = xe_eudebug_create_event(d,
					PRELIM_DRM_XE_EUDEBUG_EVENT_EXEC_QUEUE_PLACEMENTS,
					seqno, PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE, sz);
	if (!event)
		return -ENOMEM;

	e = cast_event(e, event);

	write_member(struct prelim_drm_xe_eudebug_event_exec_queue_placements, e, client_handle,
		     client_handle);
	write_member(struct prelim_drm_xe_eudebug_event_exec_queue_placements, e, vm_handle, vm_handle);
	write_member(struct prelim_drm_xe_eudebug_event_exec_queue_placements, e, exec_queue_handle,
		     exec_queue_handle);
	write_member(struct prelim_drm_xe_eudebug_event_exec_queue_placements, e, lrc_handle, lrc_handle);
	write_member(struct prelim_drm_xe_eudebug_event_exec_queue_placements, e, num_placements,
		     num_placements);

	memcpy(e->instances, instances, num_placements * sizeof(*instances));

	return xe_eudebug_queue_event(d, event);
}

static int send_exec_queue_placements_events(struct xe_eudebug *d, struct xe_exec_queue *q,
					     u64 client_handle, u64 vm_handle,
					     u64 exec_queue_handle, u64 *lrc_handles)
{

	struct drm_xe_engine_class_instance eci[XE_HW_ENGINE_MAX_INSTANCE] = {};
	unsigned long mask = q->logical_mask;
	u32 num_placements = 0;
	int ret, i, j;
	u64 seqno;

	for_each_set_bit(i, &mask, sizeof(q->logical_mask) * 8) {
		if (XE_WARN_ON(num_placements == XE_HW_ENGINE_MAX_INSTANCE))
			break;

		eci[num_placements].engine_class = xe_to_user_engine_class[q->class];
		eci[num_placements].engine_instance = i;
		eci[num_placements++].gt_id = q->gt->info.id;
	}

	ret = 0;
	for (i = 0; i < q->width; i++) {
		seqno = atomic_long_inc_return(&d->events.seqno);

		ret = send_exec_queue_placements_event(d, client_handle, vm_handle,
						       exec_queue_handle, lrc_handles[i],
						       num_placements, (u64 *)eci, seqno);
		if (ret)
			return ret;

		/*
		 * Parallel submissions must be logically contiguous,
		 * so the next placement is just q->logical_mask >> 1
		 */
		for (j = 0; j < num_placements; j++) {
			eci[j].engine_instance++;
			XE_WARN_ON(eci[j].engine_instance >= XE_HW_ENGINE_MAX_INSTANCE);
		}
	}

	return ret;
}

static int exec_queue_create_events(struct xe_eudebug *d,
				    struct xe_file *xef, struct xe_exec_queue *q)
{
	int h_c, h_vm, h_queue;
	u64 h_lrc[XE_HW_ENGINE_MAX_INSTANCE], seqno;
	int i;
	int ret = 0;

	if (!xe_exec_queue_is_debuggable(q))
		return 0;

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, xef);
	if (h_c < 0)
		return h_c;

	h_vm = find_handle(d->res, XE_EUDEBUG_RES_TYPE_VM, q->vm);
	if (h_vm < 0)
		return h_vm;

	if (XE_WARN_ON(q->width >= XE_HW_ENGINE_MAX_INSTANCE))
		return -EINVAL;

	for (i = 0; i < q->width; i++) {
		int h, ret;

		ret = _xe_eudebug_add_handle(d,
					     XE_EUDEBUG_RES_TYPE_LRC,
					     q->lrc[i],
					     NULL,
					     &h);

		if (ret < 0 && ret != -EEXIST)
			return ret;

		XE_WARN_ON(!h);

		h_lrc[i] = h;
	}

	h_queue = xe_eudebug_add_handle(d, XE_EUDEBUG_RES_TYPE_EXEC_QUEUE, q, &seqno);
	if (h_queue <= 0)
		return h_queue;

	/* No need to cleanup for added handles on error as if we fail
	 * we disconnect
	 */

	ret = send_exec_queue_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE,
				  h_c, h_vm, h_queue, q->class,
				  q->width, h_lrc, seqno);

	if (ret)
		return ret;

	return send_exec_queue_placements_events(d, q, h_c, h_vm, h_queue, h_lrc);
}

static int exec_queue_destroy_event(struct xe_eudebug *d,
				    struct xe_file *xef,
				    struct xe_exec_queue *q)
{
	int h_c, h_vm, h_queue;
	u64 h_lrc[XE_HW_ENGINE_MAX_INSTANCE], seqno;
	int i;

	if (!xe_exec_queue_is_debuggable(q))
		return 0;

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, xef);
	if (h_c < 0)
		return h_c;

	h_vm = find_handle(d->res, XE_EUDEBUG_RES_TYPE_VM, q->vm);
	if (h_vm < 0)
		return h_vm;

	if (XE_WARN_ON(q->width >= XE_HW_ENGINE_MAX_INSTANCE))
		return -EINVAL;

	h_queue = xe_eudebug_remove_handle(d,
					   XE_EUDEBUG_RES_TYPE_EXEC_QUEUE,
					   q,
					   &seqno);
	if (h_queue <= 0)
		return h_queue;

	for (i = 0; i < q->width; i++) {
		int ret;

		ret = _xe_eudebug_remove_handle(d,
						XE_EUDEBUG_RES_TYPE_LRC,
						q->lrc[i],
						NULL);
		if (ret < 0 && ret != -ENOENT)
			return ret;

		XE_WARN_ON(!ret);

		h_lrc[i] = ret;
	}

	return send_exec_queue_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_DESTROY,
				     h_c, h_vm, h_queue, q->class,
				     q->width, h_lrc, seqno);
}

void prelim_xe_eudebug_exec_queue_create(struct xe_file *xef, struct xe_exec_queue *q)
{
	struct xe_eudebug *d;

	if (!exec_queue_class_is_tracked(q->class))
		return;

	d = prelim_xe_eudebug_get(xef);
	if (!d)
		return;

	xe_eudebug_event_put(d, exec_queue_create_events(d, xef, q));
}

void prelim_xe_eudebug_exec_queue_destroy(struct xe_file *xef, struct xe_exec_queue *q)
{
	struct xe_eudebug *d;

	if (!exec_queue_class_is_tracked(q->class))
		return;

	d = prelim_xe_eudebug_get(xef);
	if (!d)
		return;

	xe_eudebug_event_put(d, exec_queue_destroy_event(d, xef, q));
}

static int xe_eudebug_queue_bind_event(struct xe_eudebug *d,
				       struct xe_vm *vm,
				       struct xe_eudebug_event *event)
{
	struct xe_eudebug_event_envelope *env;

	lockdep_assert_held_write(&vm->lock);

	env = kmalloc(sizeof(*env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;

	INIT_LIST_HEAD(&env->link);
	env->event = event;

	spin_lock(&vm->eudebug.lock);
	list_add_tail(&env->link, &vm->eudebug.events);

	if (event->type == PRELIM_DRM_XE_EUDEBUG_EVENT_VM_BIND_OP)
		++vm->eudebug.ops;
	spin_unlock(&vm->eudebug.lock);

	return 0;
}

static int queue_vm_bind_event(struct xe_eudebug *d,
			       struct xe_vm *vm,
			       u64 client_handle,
			       u64 vm_handle,
			       u32 bind_flags,
			       u32 num_ops, u64 *seqno)
{
	struct xe_eudebug_event_vm_bind *e;
	struct xe_eudebug_event *event;
	const u32 sz = sizeof(*e);
	const u32 base_flags = PRELIM_DRM_XE_EUDEBUG_EVENT_STATE_CHANGE;

	*seqno = atomic_long_inc_return(&d->events.seqno);

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_VM_BIND,
					*seqno, base_flags, sz);
	if (!event)
		return -ENOMEM;

	e = cast_event(e, event);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind, e, client_handle, client_handle);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind, e, vm_handle, vm_handle);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind, e, flags, bind_flags);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind, e, num_binds, num_ops);

	/* If in discovery, no need to collect ops */
	if (!completion_done(&d->discovery)) {
		XE_WARN_ON(!num_ops);
		return xe_eudebug_queue_event(d, event);
	}

	return xe_eudebug_queue_bind_event(d, vm, event);
}

static int vm_bind_event(struct xe_eudebug *d,
			 struct xe_vm *vm,
			 u32 num_ops,
			 u64 *seqno)
{
	int h_c, h_vm;

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, vm->xef);
	if (h_c < 0)
		return h_c;

	h_vm = find_handle(d->res, XE_EUDEBUG_RES_TYPE_VM, vm);
	if (h_vm < 0)
		return h_vm;

	return queue_vm_bind_event(d, vm, h_c, h_vm, 0,
				   num_ops, seqno);
}

static int vm_bind_op_event(struct xe_eudebug *d,
			    struct xe_vm *vm,
			    const u32 flags,
			    const u64 bind_ref_seqno,
			    const u64 num_extensions,
			    u64 addr, u64 range,
			    u64 *op_seqno)
{
	struct xe_eudebug_event_vm_bind_op *e;
	struct xe_eudebug_event *event;
	const u32 sz = sizeof(*e);

	*op_seqno = atomic_long_inc_return(&d->events.seqno);

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_VM_BIND_OP,
					*op_seqno, flags, sz);
	if (!event)
		return -ENOMEM;

	e = cast_event(e, event);

	write_member(struct prelim_drm_xe_eudebug_event_vm_bind_op, e, vm_bind_ref_seqno, bind_ref_seqno);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind_op, e, num_extensions, num_extensions);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind_op, e, addr, addr);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind_op, e, range, range);

	/* If in discovery, no need to collect ops */
	if (!completion_done(&d->discovery))
		return xe_eudebug_queue_event(d, event);

	return xe_eudebug_queue_bind_event(d, vm, event);
}

static int vm_bind_op_metadata_event(struct xe_eudebug *d,
				     struct xe_vm *vm,
				     u32 flags,
				     u64 ref_seqno,
				     u64 metadata_handle,
				     u64 metadata_cookie)
{
	struct xe_eudebug_event_vm_bind_op_metadata *e;
	struct xe_eudebug_event *event;
	const u32 sz = sizeof(*e);
	u64 seqno;

	seqno = atomic_long_inc_return(&d->events.seqno);

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_VM_BIND_OP_METADATA,
					seqno, flags, sz);
	if (!event)
		return -ENOMEM;

	e = cast_event(e, event);

	write_member(struct prelim_drm_xe_eudebug_event_vm_bind_op_metadata, e,
		     vm_bind_op_ref_seqno, ref_seqno);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind_op_metadata, e,
		     metadata_handle, metadata_handle);
	write_member(struct prelim_drm_xe_eudebug_event_vm_bind_op_metadata, e,
		     metadata_cookie, metadata_cookie);

	/* If in discovery, no need to collect ops */
	if (!completion_done(&d->discovery))
		return xe_eudebug_queue_event(d, event);

	return xe_eudebug_queue_bind_event(d, vm, event);
}

static int vm_bind_op_metadata_count(struct xe_eudebug *d,
				     struct xe_vm *vm,
				     struct list_head *debug_metadata)
{
	struct xe_vma_debug_metadata *metadata;
	struct prelim_xe_debug_metadata *mdata;
	int h_m = 0, metadata_count = 0;

	if (!debug_metadata)
		return 0;

	list_for_each_entry(metadata, debug_metadata, link) {
		mdata = prelim_xe_debug_metadata_get(vm->xef, metadata->metadata_id);
		if (mdata) {
			h_m = find_handle(d->res, XE_EUDEBUG_RES_TYPE_METADATA, mdata);
			prelim_xe_debug_metadata_put(mdata);
		}

		if (!mdata || h_m < 0) {
			if (!mdata) {
				eu_err(d, "Metadata::%u not found.",
				       metadata->metadata_id);
			} else {
				eu_err(d, "Metadata::%u not in the xe debugger",
				       metadata->metadata_id);
			}
			xe_eudebug_disconnect(d, -ENOENT);
			return -ENOENT;
		}
		metadata_count++;
	}
	return metadata_count;
}

static int vm_bind_op_metadata(struct xe_eudebug *d, struct xe_vm *vm,
			       const u32 flags,
			       const u64 op_ref_seqno,
			       struct list_head *debug_metadata)
{
	struct xe_vma_debug_metadata *metadata;
	int h_m = 0; /* handle space range = <1, MAX_INT>, return 0 if metadata not attached */
	int metadata_count = 0;
	int ret;

	if (!debug_metadata)
		return 0;

	XE_WARN_ON(flags != PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE);

	list_for_each_entry(metadata, debug_metadata, link) {
		struct prelim_xe_debug_metadata *mdata;

		mdata = prelim_xe_debug_metadata_get(vm->xef, metadata->metadata_id);
		if (mdata) {
			h_m = find_handle(d->res, XE_EUDEBUG_RES_TYPE_METADATA, mdata);
			prelim_xe_debug_metadata_put(mdata);
		}

		if (!mdata || h_m < 0) {
			eu_err(d, "Attached debug metadata::%u not found!\n",
			       metadata->metadata_id);
			return -ENOENT;
		}

		ret = vm_bind_op_metadata_event(d, vm, flags, op_ref_seqno,
						h_m, metadata->cookie);
		if (ret < 0)
			return ret;

		metadata_count++;
	}

	return metadata_count;
}

static int vm_bind_op(struct xe_eudebug *d, struct xe_vm *vm,
		      const u32 flags, const u64 bind_ref_seqno,
		      u64 addr, u64 range,
		      struct list_head *debug_metadata)
{
	u64 op_seqno = 0;
	u64 num_extensions;
	int ret;

	ret = vm_bind_op_metadata_count(d, vm, debug_metadata);
	if (ret < 0)
		return ret;

	num_extensions = ret;

	ret = vm_bind_op_event(d, vm, flags, bind_ref_seqno, num_extensions,
			       addr, range, &op_seqno);
	if (ret)
		return ret;

	ret = vm_bind_op_metadata(d, vm, flags, op_seqno, debug_metadata);
	if (ret < 0)
		return ret;

	if (ret != num_extensions) {
		eu_err(d, "Inconsistency in metadata detected.");
		return -EINVAL;
	}

	return 0;
}

static int xe_eudebug_track_ufence(struct xe_eudebug *d,
				   struct xe_user_fence *f,
				   u64 seqno)
{
	struct xe_eudebug_ack *ack;
	struct rb_node *old;

	ack = kzalloc(sizeof(*ack), GFP_KERNEL);
	if (!ack)
		return -ENOMEM;

	ack->seqno = seqno;
	ack->ts_insert = ktime_get();

	spin_lock(&d->acks.lock);
	old = rb_find_add(&ack->rb_node,
			  &d->acks.tree, ack_insert_cmp);
	if (!old) {
		kref_get(&f->refcount);
		ack->ufence = f;
	}
	spin_unlock(&d->acks.lock);

	if (old) {
		eu_dbg(d, "ACK: seqno=%llu: already exists", seqno);
		kfree(ack);
		return -EEXIST;
	}

	eu_dbg(d, "ACK: seqno=%llu: tracking started", seqno);

	return 0;
}

static int vm_bind_ufence_event(struct xe_eudebug *d,
				struct xe_user_fence *ufence)
{
	struct xe_eudebug_event *event;
	struct xe_eudebug_event_vm_bind_ufence *e;
	const u32 sz = sizeof(*e);
	const u32 flags = PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE |
		PRELIM_DRM_XE_EUDEBUG_EVENT_NEED_ACK;
	u64 seqno;
	int ret;

	seqno = atomic_long_inc_return(&d->events.seqno);

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_VM_BIND_UFENCE,
					seqno, flags, sz);
	if (!event)
		return -ENOMEM;

	e = cast_event(e, event);

	write_member(struct prelim_drm_xe_eudebug_event_vm_bind_ufence,
		     e, vm_bind_ref_seqno, ufence->eudebug.bind_ref_seqno);

	ret = xe_eudebug_track_ufence(d, ufence, seqno);
	if (!ret)
		ret = xe_eudebug_queue_event(d, event);

	return ret;
}

void prelim_xe_eudebug_vm_init(struct xe_vm *vm)
{
	INIT_LIST_HEAD(&vm->eudebug.events);
	spin_lock_init(&vm->eudebug.lock);
	vm->eudebug.ops = 0;
	vm->eudebug.ref_seqno = 0;
}

void prelim_xe_eudebug_vm_bind_start(struct xe_vm *vm)
{
	struct xe_eudebug *d;
	u64 seqno = 0;
	int err;

	if (!xe_vm_in_lr_mode(vm))
		return;

	d = prelim_xe_eudebug_get(vm->xef);
	if (!d)
		return;

	lockdep_assert_held_write(&vm->lock);

	if (XE_WARN_ON(!list_empty(&vm->eudebug.events)) ||
	    XE_WARN_ON(vm->eudebug.ops) ||
	    XE_WARN_ON(vm->eudebug.ref_seqno)) {
		eu_err(d, "bind busy on %s",  __func__);
		xe_eudebug_disconnect(d, -EINVAL);
	}

	err = vm_bind_event(d, vm, 0, &seqno);
	if (err) {
		eu_err(d, "error %d on %s", err, __func__);
		xe_eudebug_disconnect(d, err);
	}

	spin_lock(&vm->eudebug.lock);
	XE_WARN_ON(vm->eudebug.ref_seqno);
	vm->eudebug.ref_seqno = seqno;
	vm->eudebug.ops = 0;
	spin_unlock(&vm->eudebug.lock);

	prelim_xe_eudebug_put(d);
}

void prelim_xe_eudebug_vm_bind_op_add(struct xe_vm *vm, u32 op, u64 addr, u64 range,
			       struct drm_gpuva_ops *ops)
{
	struct xe_eudebug *d;
	struct list_head *debug_metadata = NULL;
	u32 flags;

	if (!xe_vm_in_lr_mode(vm))
		return;

	switch (op) {
	case DRM_XE_VM_BIND_OP_MAP:
	case DRM_XE_VM_BIND_OP_MAP_USERPTR:
	{
		struct drm_gpuva_op *__op;

		flags = PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE;

		/* OP_MAP will be last and singleton */
		drm_gpuva_for_each_op(__op, ops) {
			struct xe_vma_op *op = gpuva_op_to_vma_op(__op);

			if (op->base.op == DRM_GPUVA_OP_MAP)
				debug_metadata = &op->map.vma->eudebug.metadata.list;
		}
		break;
	}
	case DRM_XE_VM_BIND_OP_UNMAP:
	case DRM_XE_VM_BIND_OP_UNMAP_ALL:
		flags = PRELIM_DRM_XE_EUDEBUG_EVENT_DESTROY;
		break;
	default:
		flags = 0;
		break;
	}

	if (!flags)
		return;

	d = prelim_xe_eudebug_get(vm->xef);
	if (!d)
		return;

	xe_eudebug_event_put(d, vm_bind_op(d, vm, flags, 0, addr, range,
					   debug_metadata));
}

static struct xe_eudebug_event *fetch_bind_event(struct xe_vm * const vm)
{
	struct xe_eudebug_event_envelope *env;
	struct xe_eudebug_event *e = NULL;

	spin_lock(&vm->eudebug.lock);
	env = list_first_entry_or_null(&vm->eudebug.events,
				       struct xe_eudebug_event_envelope, link);
	if (env) {
		e = env->event;
		list_del(&env->link);
	}
	spin_unlock(&vm->eudebug.lock);

	kfree(env);

	return e;
}

static void fill_vm_bind_fields(struct xe_vm *vm,
				struct xe_eudebug_event *e,
				bool ufence,
				u32 bind_ops)
{
	struct xe_eudebug_event_vm_bind *eb = cast_event(eb, e);

	eb->flags = ufence ?
		PRELIM_DRM_XE_EUDEBUG_EVENT_VM_BIND_FLAG_UFENCE : 0;
	eb->num_binds = bind_ops;
}

static void fill_vm_bind_op_fields(struct xe_vm *vm,
				   struct xe_eudebug_event *e,
				   u64 ref_seqno)
{
	struct xe_eudebug_event_vm_bind_op *op;

	if (e->type != PRELIM_DRM_XE_EUDEBUG_EVENT_VM_BIND_OP)
		return;

	op = cast_event(op, e);
	op->vm_bind_ref_seqno = ref_seqno;
}

void prelim_xe_eudebug_vm_bind_end(struct xe_vm *vm, bool has_ufence, int bind_err)
{
	struct xe_eudebug_event *e;
	struct xe_eudebug *d;
	u32 bind_ops;
	u64 ref;

	if (!xe_vm_in_lr_mode(vm))
		return;

	spin_lock(&vm->eudebug.lock);
	ref = vm->eudebug.ref_seqno;
	vm->eudebug.ref_seqno = 0;
	bind_ops = vm->eudebug.ops;
	vm->eudebug.ops = 0;
	spin_unlock(&vm->eudebug.lock);

	e = fetch_bind_event(vm);
	if (!e)
		return;

	d = NULL;
	if (!bind_err && ref) {
		d = prelim_xe_eudebug_get(vm->xef);
		if (d) {
			if (bind_ops) {
				fill_vm_bind_fields(vm, e, has_ufence, bind_ops);
			} else {
				/*
				 * If there was no ops we are interested in,
				 * we can omit the whole sequence
				 */
				prelim_xe_eudebug_put(d);
				d = NULL;
			}
		}
	}

	while (e) {
		int err = 0;

		if (d) {
			err = xe_eudebug_queue_event(d, e);
			if (!err)
				e = NULL;
		}

		if (err) {
			xe_eudebug_disconnect(d, err);
			prelim_xe_eudebug_put(d);
			d = NULL;
		}

		kfree(e);

		e = fetch_bind_event(vm);
		if (e && ref)
			fill_vm_bind_op_fields(vm, e, ref);
	}

	if (d)
		prelim_xe_eudebug_put(d);
}

int prelim_xe_eudebug_vm_bind_ufence(struct xe_user_fence *ufence)
{
	struct xe_eudebug *d;
	int err;

	d = ufence->eudebug.debugger;
	if (!d || xe_eudebug_detached(d))
		return -ENOTCONN;

	err = vm_bind_ufence_event(d, ufence);
	if (err) {
		eu_err(d, "error %d on %s", err, __func__);
		xe_eudebug_disconnect(d, err);
	}

	return err;
}

static int send_debug_metadata_event(struct xe_eudebug *d, u32 flags,
				     u64 client_handle, u64 metadata_handle,
				     u64 type, u64 len, u64 seqno)
{
	struct xe_eudebug_event *event;
	struct xe_eudebug_event_metadata *e;

	event = xe_eudebug_create_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_METADATA, seqno,
					flags, sizeof(*e));
	if (!event)
		return -ENOMEM;

	e = cast_event(e, event);

	write_member(struct prelim_drm_xe_eudebug_event_metadata, e, client_handle, client_handle);
	write_member(struct prelim_drm_xe_eudebug_event_metadata, e, metadata_handle, metadata_handle);
	write_member(struct prelim_drm_xe_eudebug_event_metadata, e, type, type);
	write_member(struct prelim_drm_xe_eudebug_event_metadata, e, len, len);

	return xe_eudebug_queue_event(d, event);
}

static int debug_metadata_create_event(struct xe_eudebug *d,
				       struct xe_file *xef, struct prelim_xe_debug_metadata *m)
{
	int h_c, h_m;
	u64 seqno;

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, xef);
	if (h_c < 0)
		return h_c;

	h_m = xe_eudebug_add_handle(d, XE_EUDEBUG_RES_TYPE_METADATA, m, &seqno);
	if (h_m <= 0)
		return h_m;

	return send_debug_metadata_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE,
					 h_c, h_m, m->type, m->len, seqno);
}

static int debug_metadata_destroy_event(struct xe_eudebug *d,
					struct xe_file *xef, struct prelim_xe_debug_metadata *m)
{
	int h_c, h_m;
	u64 seqno;

	h_c = find_handle(d->res, XE_EUDEBUG_RES_TYPE_CLIENT, xef);
	if (h_c < 0)
		return h_c;

	h_m = xe_eudebug_remove_handle(d, XE_EUDEBUG_RES_TYPE_METADATA, m, &seqno);
	if (h_m < 0)
		return h_m;

	return send_debug_metadata_event(d, PRELIM_DRM_XE_EUDEBUG_EVENT_DESTROY,
					 h_c, h_m, m->type, m->len, seqno);
}

void prelim_xe_eudebug_debug_metadata_create(struct xe_file *xef, struct prelim_xe_debug_metadata *m)
{
	struct xe_eudebug *d;

	d = prelim_xe_eudebug_get(xef);
	if (!d)
		return;

	xe_eudebug_event_put(d, debug_metadata_create_event(d, xef, m));
}

void prelim_xe_eudebug_debug_metadata_destroy(struct xe_file *xef, struct prelim_xe_debug_metadata *m)
{
	struct xe_eudebug *d;

	d = prelim_xe_eudebug_get(xef);
	if (!d)
		return;

	xe_eudebug_event_put(d, debug_metadata_destroy_event(d, xef, m));
}

static int vm_discover_binds(struct xe_eudebug *d, struct xe_vm *vm)
{
	struct drm_gpuva *va;
	unsigned int num_ops = 0, send_ops = 0;
	u64 ref_seqno = 0;
	int err;

	/*
	 * Currently only vm_bind_ioctl inserts vma's
	 * and with discovery lock, we have exclusivity.
	 */
	lockdep_assert_held_write(&d->xe->eudebug.discovery_lock);

	drm_gpuvm_for_each_va(va, &vm->gpuvm)
		num_ops++;

	if (!num_ops)
		return 0;

	err = vm_bind_event(d, vm, num_ops, &ref_seqno);
	if (err)
		return err;

	drm_gpuvm_for_each_va(va, &vm->gpuvm) {
		struct xe_vma *vma = container_of(va, struct xe_vma, gpuva);

		if (send_ops >= num_ops)
			break;

		err = vm_bind_op(d, vm, PRELIM_DRM_XE_EUDEBUG_EVENT_CREATE, ref_seqno,
				 xe_vma_start(vma), xe_vma_size(vma),
				 &vma->eudebug.metadata.list);
		if (err)
			return err;

		send_ops++;
	}

	return num_ops == send_ops ? 0 : -EINVAL;
}

static int discover_client(struct xe_eudebug *d, struct xe_file *xef)
{
	struct prelim_xe_debug_metadata *m;
	struct xe_exec_queue *q;
	struct xe_vm *vm;
	unsigned long i;
	int err;

	err = client_create_event(d, xef);
	if (err)
		return err;

	xa_for_each(&xef->eudebug.metadata.xa, i, m) {
		err = debug_metadata_create_event(d, xef, m);
		if (err)
			break;
	}

	xa_for_each(&xef->vm.xa, i, vm) {
		err = vm_create_event(d, xef, vm);
		if (err)
			break;

		err = vm_discover_binds(d, vm);
		if (err)
			break;
	}

	xa_for_each(&xef->exec_queue.xa, i, q) {
		if (!exec_queue_class_is_tracked(q->class))
			continue;

		err = exec_queue_create_events(d, xef, q);
		if (err)
			break;
	}

	return err;
}

static bool xe_eudebug_task_match(struct xe_eudebug *d, struct xe_file *xef)
{
	struct task_struct *task;
	bool match;

	task = find_task_get(xef);
	if (!task)
		return false;

	match = same_thread_group(d->target_task, task);

	put_task_struct(task);

	return match;
}

static void discover_clients(struct xe_device *xe, struct xe_eudebug *d)
{
	struct xe_file *xef;
	int err;

	list_for_each_entry(xef, &xe->clients.list, eudebug.client_link) {
		if (xe_eudebug_detached(d))
			break;

		if (xe_eudebug_task_match(d, xef))
			err = discover_client(d, xef);
		else
			err = 0;

		if (err) {
			eu_dbg(d, "discover client %p: %d\n", xef, err);
			break;
		}
	}
}

static void discovery_work_fn(struct work_struct *work)
{
	struct xe_eudebug *d = container_of(work, typeof(*d),
					    discovery_work);
	struct xe_device *xe = d->xe;

	if (xe_eudebug_detached(d)) {
		complete_all(&d->discovery);
		prelim_xe_eudebug_put(d);
		return;
	}

	down_write(&xe->eudebug.discovery_lock);

	eu_dbg(d, "Discovery start for %lld\n", d->session);

	discover_clients(xe, d);

	eu_dbg(d, "Discovery end for %lld\n", d->session);

	complete_all(&d->discovery);

	up_write(&xe->eudebug.discovery_lock);

	send_queued_pagefault(d, false);

	prelim_xe_eudebug_put(d);
}

void prelim_xe_eudebug_ufence_init(struct xe_user_fence *ufence,
			    struct xe_file *xef,
			    struct xe_vm *vm)
{
	u64 bind_ref;

	/* Drop if OA */
	if (!vm)
		return;

	spin_lock(&vm->eudebug.lock);
	bind_ref = vm->eudebug.ref_seqno;
	spin_unlock(&vm->eudebug.lock);

	spin_lock_init(&ufence->eudebug.lock);
	INIT_WORK(&ufence->eudebug.worker, ufence_signal_worker);

	ufence->eudebug.signalled_seqno = 0;

	if (bind_ref) {
		ufence->eudebug.debugger = prelim_xe_eudebug_get(xef);

		if (ufence->eudebug.debugger)
			ufence->eudebug.bind_ref_seqno = bind_ref;
	}
}

void prelim_xe_eudebug_ufence_fini(struct xe_user_fence *ufence)
{
	if (!ufence->eudebug.debugger)
		return;

	prelim_xe_eudebug_put(ufence->eudebug.debugger);
	ufence->eudebug.debugger = NULL;
}

static int xe_eudebug_vma_access(struct xe_vma *vma, u64 offset_in_vma,
				 void *buf, u64 len, bool write)
{
	struct xe_bo *bo;
	u64 bytes;

	lockdep_assert_held_write(&xe_vma_vm(vma)->lock);

	if (XE_WARN_ON(offset_in_vma >= xe_vma_size(vma)))
		return -EINVAL;

	bytes = min_t(u64, len, xe_vma_size(vma) - offset_in_vma);
	if (!bytes)
		return 0;

	bo = xe_bo_get(xe_vma_bo(vma));
	if (bo) {
		int ret;

		ret = ttm_bo_access(&bo->ttm, offset_in_vma, buf, bytes, write);

		xe_bo_put(bo);

		return ret;
	}

	return xe_vm_userptr_access(to_userptr_vma(vma), offset_in_vma,
				    buf, bytes, write);
}

static int xe_eudebug_vm_access(struct xe_vm *vm, u64 offset,
				void *buf, u64 len, bool write)
{
	struct xe_vma *vma;
	int ret;

	down_write(&vm->lock);

	vma = xe_vm_find_overlapping_vma(vm, offset, len);
	if (vma) {
		/* XXX: why find overlapping returns below start? */
		if (offset < xe_vma_start(vma) ||
		    offset >= (xe_vma_start(vma) + xe_vma_size(vma))) {
			ret = -EINVAL;
			goto out;
		}

		/* Offset into vma */
		offset -= xe_vma_start(vma);
		ret = xe_eudebug_vma_access(vma, offset, buf, len, write);
	} else {
		ret = -EINVAL;
	}

out:
	up_write(&vm->lock);

	return ret;
}

struct vm_file {
	struct xe_eudebug *debugger;
	struct xe_file *xef;
	struct xe_vm *vm;
	u64 flags;
	u64 client_id;
	u64 vm_handle;
	unsigned int timeout_us;
};

static ssize_t __vm_read_write(struct xe_vm *vm,
			       void *bb,
			       char __user *r_buffer,
			       const char __user *w_buffer,
			       unsigned long offset,
			       unsigned long len,
			       const bool write)
{
	ssize_t ret;

	if (!len)
		return 0;

	if (write) {
		ret = copy_from_user(bb, w_buffer, len);
		if (ret)
			return -EFAULT;

		ret = xe_eudebug_vm_access(vm, offset, bb, len, true);
		if (ret < 0)
			return ret;

		len = ret;
	} else {
		ret = xe_eudebug_vm_access(vm, offset, bb, len, false);
		if (ret < 0)
			return ret;

		len = ret;

		ret = copy_to_user(r_buffer, bb, len);
		if (ret)
			return -EFAULT;
	}

	return len;
}

static struct xe_vm *find_vm_get(struct xe_eudebug *d, const u32 id)
{
	struct xe_vm *vm;

	mutex_lock(&d->res->lock);
	vm = find_resource__unlocked(d->res, XE_EUDEBUG_RES_TYPE_VM, id);
	if (vm)
		xe_vm_get(vm);

	mutex_unlock(&d->res->lock);

	return vm;
}

static ssize_t __xe_eudebug_vm_access(struct file *file,
				      char __user *r_buffer,
				      const char __user *w_buffer,
				      size_t count, loff_t *__pos)
{
	struct vm_file *vmf = file->private_data;
	struct xe_eudebug * const d = vmf->debugger;
	struct xe_device * const xe = d->xe;
	const bool write = !!w_buffer;
	struct xe_vm *vm;
	ssize_t copied = 0;
	ssize_t bytes_left = count;
	ssize_t ret;
	unsigned long alloc_len;
	loff_t pos = *__pos;
	void *k_buffer;

	if (XE_IOCTL_DBG(xe, write && r_buffer))
		return -EINVAL;

	vm = find_vm_get(d, vmf->vm_handle);
	if (XE_IOCTL_DBG(xe, !vm))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, vm != vmf->vm)) {
		eu_warn(d, "vm_access(%s): vm handle mismatch client_handle=%llu, vm_handle=%llu, flags=0x%llx, pos=%llu, count=%zu\n",
			write ? "write" : "read",
			vmf->client_id, vmf->vm_handle, vmf->flags, pos, count);
		xe_vm_put(vm);
		return -EINVAL;
	}

	if (!count) {
		xe_vm_put(vm);
		return 0;
	}

	alloc_len = min_t(unsigned long, ALIGN(count, PAGE_SIZE), 64 * SZ_1M);
	do  {
		k_buffer = vmalloc(alloc_len);
		if (k_buffer)
			break;

		alloc_len >>= 1;
	} while (alloc_len > PAGE_SIZE);

	if (XE_IOCTL_DBG(xe, !k_buffer)) {
		xe_vm_put(vm);
		return -ENOMEM;
	}

	do {
		const ssize_t len = min_t(ssize_t, bytes_left, alloc_len);

		ret = __vm_read_write(vm, k_buffer,
				      write ? NULL : r_buffer + copied,
				      write ? w_buffer + copied : NULL,
				      pos + copied,
				      len,
				      write);
		if (ret <= 0)
			break;

		bytes_left -= ret;
		copied += ret;
	} while (bytes_left > 0);

	vfree(k_buffer);
	xe_vm_put(vm);

	if (XE_WARN_ON(copied < 0))
		copied = 0;

	*__pos += copied;

	return copied ?: ret;
}

static ssize_t xe_eudebug_vm_read(struct file *file,
				  char __user *buffer,
				  size_t count, loff_t *pos)
{
	return __xe_eudebug_vm_access(file, buffer, NULL, count, pos);
}

static ssize_t xe_eudebug_vm_write(struct file *file,
				   const char __user *buffer,
				   size_t count, loff_t *pos)
{
	return __xe_eudebug_vm_access(file, NULL, buffer, count, pos);
}

static int engine_rcu_flush(struct xe_eudebug *d,
			    struct xe_hw_engine *hwe,
			    unsigned int timeout_us)
{
	const struct xe_reg psmi_addr = RING_PSMI_CTL(hwe->mmio_base);
	struct xe_gt *gt = hwe->gt;
	unsigned int fw_ref;
	u32 mask = RCU_ASYNC_FLUSH_AND_INVALIDATE_ALL;
	u32 psmi_ctrl;
	u32 id;
	int ret;

	if (hwe->class == XE_ENGINE_CLASS_RENDER)
		id = 0;
	else if (hwe->class == XE_ENGINE_CLASS_COMPUTE)
		id = hwe->instance + 1;
	else
		return -EINVAL;

	if (id < 8)
		mask |= id << RCU_ASYNC_FLUSH_ENGINE_ID_SHIFT;
	else
		mask |= (id - 8) << RCU_ASYNC_FLUSH_ENGINE_ID_SHIFT |
			RCU_ASYNC_FLUSH_ENGINE_ID_DECODE1;

	fw_ref = xe_force_wake_get(gt_to_fw(gt), hwe->domain);
	if (!fw_ref)
		return -ETIMEDOUT;

	/* Prevent concurrent flushes */
	mutex_lock(&d->eu_lock);
	psmi_ctrl = xe_mmio_read32(&gt->mmio, psmi_addr);
	if (!(psmi_ctrl & IDLE_MSG_DISABLE))
		xe_mmio_write32(&gt->mmio, psmi_addr, _MASKED_BIT_ENABLE(IDLE_MSG_DISABLE));

	/* XXX: Timeout is per operation but in here we flush previous */
	ret = xe_mmio_wait32(&gt->mmio, RCU_ASYNC_FLUSH,
			     RCU_ASYNC_FLUSH_IN_PROGRESS, 0,
			     timeout_us, NULL, false);
	if (ret)
		goto out;

	xe_mmio_write32(&gt->mmio, RCU_ASYNC_FLUSH, mask);

	ret = xe_mmio_wait32(&gt->mmio, RCU_ASYNC_FLUSH,
			     RCU_ASYNC_FLUSH_IN_PROGRESS, 0,
			     timeout_us, NULL, false);
out:
	if (!(psmi_ctrl & IDLE_MSG_DISABLE))
		xe_mmio_write32(&gt->mmio, psmi_addr, _MASKED_BIT_DISABLE(IDLE_MSG_DISABLE));

	mutex_unlock(&d->eu_lock);
	xe_force_wake_put(gt_to_fw(gt), fw_ref);

	return ret;
}

static int xe_eudebug_vm_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct vm_file *vmf = file->private_data;
	struct xe_eudebug *d = vmf->debugger;
	struct xe_gt *gt;
	int gt_id;
	int ret = -EINVAL;

	eu_dbg(d, "vm_fsync: client_handle=%llu, vm_handle=%llu, flags=0x%llx, start=%llu, end=%llu datasync=%d\n",
	       vmf->client_id, vmf->vm_handle, vmf->flags, start, end, datasync);

	for_each_gt(gt, d->xe, gt_id) {
		struct xe_hw_engine *hwe;
		enum xe_hw_engine_id id;

		/* XXX: vm open per engine? */
		for_each_hw_engine(hwe, gt, id) {
			if (hwe->class != XE_ENGINE_CLASS_RENDER &&
			    hwe->class != XE_ENGINE_CLASS_COMPUTE)
				continue;

			ret = engine_rcu_flush(d, hwe, vmf->timeout_us);
			if (ret)
				break;
		}
	}

	return ret;
}

static int xe_eudebug_vm_release(struct inode *inode, struct file *file)
{
	struct vm_file *vmf = file->private_data;
	struct xe_eudebug *d = vmf->debugger;

	eu_dbg(d, "vm_release: client_handle=%llu, vm_handle=%llu, flags=0x%llx",
	       vmf->client_id, vmf->vm_handle, vmf->flags);

	xe_vm_put(vmf->vm);
	xe_file_put(vmf->xef);
	prelim_xe_eudebug_put(d);
	drm_dev_put(&d->xe->drm);

	kfree(vmf);

	return 0;
}

static const struct file_operations vm_fops = {
	.owner   = THIS_MODULE,
	.llseek  = generic_file_llseek,
	.read    = xe_eudebug_vm_read,
	.write   = xe_eudebug_vm_write,
	.fsync   = xe_eudebug_vm_fsync,
	.mmap    = NULL,
	.release = xe_eudebug_vm_release,
};

static long
xe_eudebug_vm_open_ioctl(struct xe_eudebug *d, unsigned long arg)
{
	const u64 max_timeout_ns = PRELIM_DRM_XE_EUDEBUG_VM_SYNC_MAX_TIMEOUT_NSECS;
	struct prelim_drm_xe_eudebug_vm_open param;
	struct xe_device * const xe = d->xe;
	struct vm_file *vmf = NULL;
	struct xe_file *xef;
	struct xe_vm *vm;
	struct file *file;
	long ret = 0;
	int fd;

	if (XE_IOCTL_DBG(xe, _IOC_SIZE(PRELIM_DRM_XE_EUDEBUG_IOCTL_VM_OPEN) != sizeof(param)))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, !(_IOC_DIR(PRELIM_DRM_XE_EUDEBUG_IOCTL_VM_OPEN) & _IOC_WRITE)))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, copy_from_user(&param, (void __user *)arg, sizeof(param))))
		return -EFAULT;

	if (XE_IOCTL_DBG(xe, param.flags))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, param.timeout_ns > max_timeout_ns))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, xe_eudebug_detached(d)))
		return -ENOTCONN;

	xef = find_client_get(d, param.client_handle);
	if (xef)
		vm = find_vm_get(d, param.vm_handle);
	else
		vm = NULL;

	if (XE_IOCTL_DBG(xe, !xef))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, !vm)) {
		ret = -EINVAL;
		goto out_file_put;
	}

	vmf = kzalloc(sizeof(*vmf), GFP_KERNEL);
	if (XE_IOCTL_DBG(xe, !vmf)) {
		ret = -ENOMEM;
		goto out_vm_put;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (XE_IOCTL_DBG(xe, fd < 0)) {
		ret = fd;
		goto out_free;
	}

	kref_get(&d->ref);
	vmf->debugger = d;
	vmf->vm = vm;
	vmf->xef = xef;
	vmf->flags = param.flags;
	vmf->client_id = param.client_handle;
	vmf->vm_handle = param.vm_handle;
	vmf->timeout_us = div64_u64(param.timeout_ns, 1000ull);

	file = anon_inode_getfile("[xe_eudebug.vm]", &vm_fops, vmf, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		XE_IOCTL_DBG(xe, ret);
		file = NULL;
		goto out_fd_put;
	}

	file->f_mode |= FMODE_PREAD | FMODE_PWRITE |
		FMODE_READ | FMODE_WRITE | FMODE_LSEEK;

	fd_install(fd, file);

	eu_dbg(d, "vm_open: client_handle=%llu, handle=%llu, flags=0x%llx, fd=%d",
	       vmf->client_id, vmf->vm_handle, vmf->flags, fd);

	XE_WARN_ON(ret);

	drm_dev_get(&xe->drm);

	return fd;

out_fd_put:
	put_unused_fd(fd);
	prelim_xe_eudebug_put(d);
out_free:
	kfree(vmf);
out_vm_put:
	xe_vm_put(vm);
out_file_put:
	xe_file_put(xef);

	XE_WARN_ON(ret >= 0);

	return ret;
}

static int queue_pagefault(struct xe_gt *gt, struct xe_eudebug_pagefault *pf)
{
	struct xe_eudebug *d;

	if (list_empty_careful(&gt_to_xe(gt)->eudebug.list))
		return -ENOTCONN;

	d = _xe_eudebug_get(pf->q->vm->xef);
	if (IS_ERR_OR_NULL(d))
		return -EINVAL;

	mutex_lock(&d->pf_lock);
	list_add_tail(&pf->list, &d->pagefaults);
	mutex_unlock(&d->pf_lock);

	prelim_xe_eudebug_put(d);

	return 0;
}

static int handle_pagefault(struct xe_gt *gt, struct xe_eudebug_pagefault *pf)
{
	int ret;

	ret = send_pagefault(gt, pf, false);

	/*
	 * if debugger discovery is not completed or resolved attentions are not
	 * updated, then queue pagefault
	 */
	if (ret == -EBUSY) {
		ret = queue_pagefault(gt, pf);
		if (!ret)
			goto out;
	}

	xe_exec_queue_put(pf->q);
	kfree(pf);

out:
	return ret;
}

static const char *
pagefault_get_driver_name(struct dma_fence *dma_fence)
{
	return "xe";
}

static const char *
pagefault_fence_get_timeline_name(struct dma_fence *dma_fence)
{
	return "eudebug_pagefault_fence";
}

static const struct dma_fence_ops pagefault_fence_ops = {
	.get_driver_name = pagefault_get_driver_name,
	.get_timeline_name = pagefault_fence_get_timeline_name,
};

struct pagefault_fence {
	struct dma_fence base;
	spinlock_t lock;
};

static struct pagefault_fence *pagefault_fence_create(void)
{
	struct pagefault_fence *fence;

	fence = kzalloc(sizeof(*fence), GFP_KERNEL);
	if (fence == NULL)
		return NULL;

	spin_lock_init(&fence->lock);
	dma_fence_init(&fence->base, &pagefault_fence_ops, &fence->lock,
		       dma_fence_context_alloc(1), 1);

	return fence;
}

struct xe_eudebug_pagefault *
prelim_xe_eudebug_pagefault_create(struct xe_gt *gt, struct xe_vm *vm, u64 page_addr,
			    u8 fault_type, u8 fault_level, u8 access_type)
{
	struct pagefault_fence *pf_fence;
	struct xe_eudebug_pagefault *pf;
	struct xe_vma *vma = NULL;
	struct xe_exec_queue *q;
	struct dma_fence *fence;
	struct xe_eudebug *d;
	unsigned int fw_ref;
	int lrc_idx;
	u32 td_ctl;

	down_read(&vm->lock);
	vma = xe_gt_pagefault_lookup_vma(vm, page_addr);
	up_read(&vm->lock);

	if (vma)
		return NULL;

	d = _xe_eudebug_get(vm->xef);
	if (!d)
		return NULL;

	q = runalone_active_queue_get(gt, &lrc_idx);
	if (IS_ERR(q))
		goto err_put_eudebug;

	if (!xe_exec_queue_is_debuggable(q))
		goto err_put_exec_queue;

	fw_ref = xe_force_wake_get(gt_to_fw(gt), q->hwe->domain);
	if (!fw_ref)
		goto err_put_exec_queue;

	/*
	 * If there is no debug functionality (TD_CTL_GLOBAL_DEBUG_ENABLE, etc.),
	 * don't proceed pagefault routine for eu debugger.
	 */

	td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);
	if (!td_ctl)
		goto err_put_fw;

	pf = kzalloc(sizeof(*pf), GFP_KERNEL);
	if (!pf)
		goto err_put_fw;

	attention_scan_cancel(gt_to_xe(gt));

	mutex_lock(&d->eu_lock);
	rcu_read_lock();
	fence = dma_fence_get_rcu_safe(&d->pf_fence);
	rcu_read_unlock();

	if (fence) {
		/*
		 * TODO: If the new incoming pagefaulted address is different
		 * from the pagefaulted address it is currently handling on the
		 * same ASID, it needs a routine to wait here and then do the
		 * following pagefault.
		 */
		dma_fence_put(fence);
		goto err_unlock_eu_lock;
	}

	pf_fence = pagefault_fence_create();
	if (!pf_fence) {
		goto err_unlock_eu_lock;
	}

	d->pf_fence = &pf_fence->base;
	mutex_unlock(&d->eu_lock);

	INIT_LIST_HEAD(&pf->list);

	prelim_xe_gt_eu_attentions_read(gt, &pf->attentions.before, 0);

	/* Halt on next thread dispatch */
	while (!(td_ctl & TD_CTL_FORCE_EXTERNAL_HALT)) {
		xe_gt_mcr_multicast_write(gt, TD_CTL,
					  td_ctl | TD_CTL_FORCE_EXTERNAL_HALT);
		/*
		 * The sleep is needed because some interrupts are ignored
		 * by the HW, hence we allow the HW some time to acknowledge
		 * that.
		 */
		udelay(200);
		td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);
	}

	/* Halt regardless of thread dependencies */
	while (!(td_ctl & TD_CTL_FORCE_EXCEPTION)) {
		xe_gt_mcr_multicast_write(gt, TD_CTL,
					  td_ctl | TD_CTL_FORCE_EXCEPTION);
		udelay(200);
		td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);
	}

	prelim_xe_gt_eu_attentions_read(gt, &pf->attentions.after,
				 PRELIM_XE_GT_ATTENTION_TIMEOUT_MS);

	/*
	 * xe_exec_queue_put() will be called from prelim_xe_eudebug_pagefault_destroy()
	 * or handle_pagefault()
	 */
	pf->q = q;
	pf->lrc_idx = lrc_idx;
	pf->fault.addr = page_addr;
	pf->fault.type = fault_type;
	pf->fault.level = fault_level;
	pf->fault.access = access_type;

	xe_force_wake_put(gt_to_fw(gt), fw_ref);
	prelim_xe_eudebug_put(d);

	return pf;

err_unlock_eu_lock:
	mutex_unlock(&d->eu_lock);
	attention_scan_flush(gt_to_xe(gt));
	kfree(pf);
err_put_fw:
	xe_force_wake_put(gt_to_fw(gt), fw_ref);
err_put_exec_queue:
	xe_exec_queue_put(q);
err_put_eudebug:
	prelim_xe_eudebug_put(d);

	return NULL;
}

void
prelim_xe_eudebug_pagefault_process(struct xe_gt *gt, struct xe_eudebug_pagefault *pf)
{
	prelim_xe_gt_eu_attentions_read(gt, &pf->attentions.resolved,
				 PRELIM_XE_GT_ATTENTION_TIMEOUT_MS);

	if (!xe_eu_attentions_xor_count(&pf->attentions.after,
					&pf->attentions.resolved))
		pf->deferred_resolved = true;
}

void
prelim_xe_eudebug_pagefault_destroy(struct xe_gt *gt, struct xe_vm *vm,
			     struct xe_eudebug_pagefault *pf, bool send_event)
{
	struct xe_eudebug *d;
	unsigned int fw_ref;
	u32 td_ctl;

	fw_ref = xe_force_wake_get(gt_to_fw(gt), pf->q->hwe->domain);
	if (!fw_ref) {
		struct xe_device *xe = gt_to_xe(gt);
		drm_warn(&xe->drm, "Forcewake fail: Can not recover TD_CTL");
	} else {
		td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);
		xe_gt_mcr_multicast_write(gt, TD_CTL, td_ctl &
					  ~(TD_CTL_FORCE_EXTERNAL_HALT | TD_CTL_FORCE_EXCEPTION));
		xe_force_wake_put(gt_to_fw(gt), fw_ref);
	}

	if (send_event)
		handle_pagefault(gt, pf);

	d = _xe_eudebug_get(vm->xef);
	if (d) {
		struct dma_fence *fence;

		mutex_lock(&d->eu_lock);
		rcu_read_lock();
		fence = dma_fence_get_rcu_safe(&d->pf_fence);
		rcu_read_unlock();

		if (fence) {
			if (send_event)
				dma_fence_signal(fence);

			dma_fence_put(fence); /* deref for dma_fence_get_rcu_safe() */
			dma_fence_put(fence); /* defef for dma_fence_init() */
		}

		d->pf_fence = NULL;
		mutex_unlock(&d->eu_lock);

		prelim_xe_eudebug_put(d);
	}

	if (!send_event) {
		xe_exec_queue_put(pf->q);
		kfree(pf);
	}

	attention_scan_flush(gt_to_xe(gt));
}
