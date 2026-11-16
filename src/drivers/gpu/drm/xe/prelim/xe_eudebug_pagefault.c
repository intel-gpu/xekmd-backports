// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023-2025 Intel Corporation
 */

#include "prelim/xe_eudebug_pagefault.h"

#include <linux/delay.h>

#include "xe_gt.h"
#include "xe_exec_queue.h"
#include "xe_pagefault.h"
#include "prelim/xe_eudebug_types.h"
#include "prelim/xe_eudebug.h"
#include "xe_force_wake.h"
#include "prelim/xe_gt_debug.h"
#include "xe_gt_mcr.h"
#include "xe_gt_printk.h"
#include "regs/xe_gt_regs.h"
#include "xe_pm.h"
#include "xe_vm.h"
#include "xe_guc.h"
#include "xe_guc_submit.h"

/**
 * DOC: EU Debug page fault workaround
 *
 * When shader generates an unresolvable page fault for client under debug
 * then eudebug performs following steps:
 * - Attention register is read to get current state of hw threads ('before').
 * - TD_CTL_FORCE_EXCEPTION is set to halt all currently running hw threads
 *   ('after'). Threads that caused page fault(s) are halted by HW and will
 *   not appear in 'after' bitmask.
 * - Page fault is ACKed to GuC.
 * - All other page faults for a matching VM are processed with optional
 *   temporary null VMA insertion before and removal after processing.
 * - When there are no more matching page faults in a queue and worker's
 *   cache then:
 *   - attention register is read to get 'resolved' bitmask.
 *   - TD_CTL_FORCE_EXCEPTION is cleared
 *   - null vma is removed
 *   - event to UMD is send.
 *
 * Single EUDebug pagefault event reports only first page fault however it
 * 'handles' them all so the bitmask may contain many aggregated page faults
 * and UMD shall check all threads that transitioned from 0 ('after') to 1
 * ('resolved').
 *
 * It is assumed that only client under debug is actively running (runalone
 * mode).
 */

#define PF_ASID(pf) FIELD_GET(XE_PAGEFAULT_ASID_MASK, (pf)->consumer.id)

/* Returns true if pf was already tagged by eudebug (like early tag for svm) */
static inline bool pf_tagged(struct xe_pagefault *pf)
{
	return (u64)pf->producer.private & PRELIM_XE_EUDEBUG_PAGEFAULT_PRIVATE_EUDEBUG;
}

static struct xe_gt *
epf_to_gt(struct xe_eudebug_pagefault *epf)
{
	return epf->q->gt;
}

static inline struct xe_vm *
epf_to_vm(struct xe_eudebug_pagefault *epf)
{
	return epf->q->vm;
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
	/** @lock: protects the @base. */
	spinlock_t lock;
};

static struct pagefault_fence *pagefault_fence_create(void)
{
	struct pagefault_fence *fence;

	fence = kzalloc_obj(*fence, GFP_KERNEL);
	if (!fence)
		return NULL;

	spin_lock_init(&fence->lock);
	dma_fence_init(&fence->base, &pagefault_fence_ops, &fence->lock,
		       dma_fence_context_alloc(1), 1);

	return fence;
}

static void pagefault_set_private(struct xe_pagefault *pf,
				  struct xe_eudebug_pagefault *epf)
{
	u64 private;

	epf->private = pf->producer.private;
	private = (u64)epf | PRELIM_XE_EUDEBUG_PAGEFAULT_PRIVATE_EUDEBUG;
	pf->producer.private = (void *)private;
}

void prelim_xe_eudebug_pagefault_set_private(struct xe_pagefault *pf,
				      struct xe_vm *vm)
{
	struct xe_eudebug_pagefault *epf;
	struct xe_eudebug *d = NULL;
	struct xe_vm *lvm = NULL;

	if (!prelim_xe_eudebug_is_enabled(gt_to_xe(pf->gt)))
		return;

	/*
	 * This services the case when function is called on
	 * cache hit. The xe_pagefault_queue_work() jumps to
	 * ack_fault bypassing xe_pagefault_service().
	 */
	if (!vm) {
		lvm = xe_device_asid_to_vm(gt_to_xe(pf->gt), PF_ASID(pf));
		if (IS_ERR(lvm))
			return;

		if (!xe_vm_in_fault_mode(lvm)) {
			xe_vm_put(lvm);
			return;
		}
		vm = lvm;
	}

	/* Could be a retry from -EAGAIN handler error */
	if ((u64)pf->producer.private & PRELIM_XE_EUDEBUG_PAGEFAULT_PRIVATE_EUDEBUG)
		goto out;

	d = prelim_xe_eudebug_get_nolock_with_discovery(vm->xef);
	if (!d)
		goto out;

	mutex_lock(&d->eu_lock);
	epf = d->pf.first;
	if (epf && PF_ASID(pf) == d->pf.asid &&
	    epf_to_gt(epf) == pf->gt)
		d->pf.active++;
	else
		epf = NULL;
	mutex_unlock(&d->eu_lock);

	if (epf)
		pagefault_set_private(pf, epf);

out:
	if (d)
		prelim_xe_eudebug_put(d);

	if (lvm)
		xe_vm_put(lvm);
}

void *prelim_xe_eudebug_pagefault_get_private(void *private)
{
	if ((u64)private & PRELIM_XE_EUDEBUG_PAGEFAULT_PRIVATE_EUDEBUG) {
		struct xe_eudebug_pagefault *epf = (void *)((u64)private &
							    ~PRELIM_XE_EUDEBUG_PAGEFAULT_PRIVATE_EUDEBUG);
		return epf->private;
	}
	return private;
}

static int __set_td_ctl_fee(struct xe_gt *gt, struct xe_eudebug *d)
{
	unsigned long tdctl_timeout;
	u32 td_ctl;

	td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);
	if (!(td_ctl & TD_CTL_GLOBAL_DEBUG_ENABLE)) {
		eu_err(d, "TD_CTL_GLOBAL_DEBUG_ENABLE not set!\n");
		return -EOPNOTSUPP;
	}

	if (td_ctl & TD_CTL_FORCE_EXCEPTION) {
		eu_err(d, "Force exception set: already set!\n");
		return -EINVAL;
	}

	tdctl_timeout = jiffies + msecs_to_jiffies(PRELIM_XE_GT_ATTENTION_TIMEOUT_MS);
	/* Halt regardless of thread dependencies */
	do {
		xe_gt_mcr_multicast_write(gt, TD_CTL,
					  td_ctl | TD_CTL_FORCE_EXCEPTION);
		usleep_range(200, 220);
		td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);

		if (!(td_ctl & TD_CTL_FORCE_EXCEPTION) &&
		    time_after(jiffies, tdctl_timeout)) {
			return -ETIMEDOUT;
		}
	} while (!(td_ctl & TD_CTL_FORCE_EXCEPTION));

	return 0;
}

static int __clear_td_ctl_fee(struct xe_gt *gt, struct xe_eudebug *d)
{
	unsigned long tdctl_timeout;
	u32 td_ctl;

	td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);

	if (!(td_ctl & TD_CTL_GLOBAL_DEBUG_ENABLE)) {
		eu_err(d, "TD_CTL_GLOBAL_DEBUG_ENABLE not set!\n");
		return -EOPNOTSUPP;
	}

	if (!(td_ctl & TD_CTL_FORCE_EXCEPTION)) {
		eu_err(d, "Force exception clear: not set!\n");
		return -EINVAL;
	}

	tdctl_timeout = jiffies + msecs_to_jiffies(PRELIM_XE_GT_ATTENTION_TIMEOUT_MS);
	do {
		xe_gt_mcr_multicast_write(gt, TD_CTL, td_ctl &
					  ~(TD_CTL_FORCE_EXCEPTION));
		usleep_range(200, 220);
		td_ctl = xe_gt_mcr_unicast_read_any(gt, TD_CTL);

		if ((td_ctl & TD_CTL_FORCE_EXCEPTION) &&
		    time_after(jiffies, tdctl_timeout)) {
			return -ETIMEDOUT;
		}
	} while (td_ctl & TD_CTL_FORCE_EXCEPTION);

	return 0;
}

static void
eudebug_try_svm_remap(struct xe_vm *vm, struct xe_vma *vma)
{
	if (xe_vm_find_overlapping_vma(vm,
				       xe_vma_start(vma),
				       xe_vma_size(vma))) {
		xe_vm_destroy_vma(vma);
		return;
	}

	if (xe_vm_insert_vma(vm, vma)) {
		xe_vm_destroy_vma(vma);
		xe_vm_kill(vm, true);
	}
}

int
prelim_xe_eudebug_pagefault_start(struct xe_vm *vm, struct xe_vma *vma,
			   struct xe_pagefault *pf)
{
	struct pagefault_fence *pf_fence;
	struct xe_eudebug_pagefault *epf;
	struct xe_gt *gt = pf->gt;
	struct xe_exec_queue *q;
	struct dma_fence *fence;
	struct xe_eudebug *d;
	unsigned int fw_ref;
	int lrc_idx;

	if (GRAPHICS_VER(gt_to_xe(gt)) >= 35)
		return -EOPNOTSUPP;

	if (!prelim_xe_eudebug_is_enabled(vm->xe))
		return -EOPNOTSUPP;

	d = prelim_xe_eudebug_get_nolock_with_discovery(vm->xef);
	if (!d)
		return -ENOENT;
	/*
	 * Not as safe as locked version but protected against NULL
	 * ptr dereference.
	 */
	q = xe_gt_runalone_active_queue_get(gt, &lrc_idx);
	if (IS_ERR(q))
		goto err_put_eudebug;

	if (XE_WARN_ON(q->vm != vm))
		goto err_put_exec_queue;

	if (!xe_exec_queue_is_debuggable(q))
		goto err_put_exec_queue;

	if (vma && !xe_vma_is_cpu_addr_mirror(vma))
		goto err_put_exec_queue;

	/**
	 * Check if there is an active pagefault.
	 * If so, attach original epf to current pagefault and leave.
	 */
	mutex_lock(&d->eu_lock);

	/* For now support for single source at a time */
	if (d->pf.first &&
	    (d->pf.first->q != q || d->pf.asid != PF_ASID(pf))) {
		mutex_unlock(&d->eu_lock);
		goto err_put_exec_queue;
	}

	if (d->pf.active || d->pf.first) {
		epf = kzalloc_obj(*epf, GFP_KERNEL);
		if (!epf) {
			mutex_unlock(&d->eu_lock);
			goto err_put_exec_queue;
		}
		if (!pf_tagged(pf))
			d->pf.active++;
		INIT_LIST_HEAD(&epf->link);
		goto out_set_epf;
	}

	/* Will be enabled when d->pf.first is released */
	prelim_xe_eudebug_attention_poll_stop(gt_to_xe(gt));

	fw_ref = xe_force_wake_get(gt_to_fw(gt), q->hwe->domain);
	if (!fw_ref)
		goto err_put_exec_queue_unlock;

	epf = kzalloc_obj(*epf, GFP_KERNEL);
	if (!epf)
		goto err_put_fw;

	if (prelim_xe_gt_eu_attentions_read(gt, &epf->attentions.before, 0))
		goto err_epf;

	if (__set_td_ctl_fee(gt, d))
		goto err_epf;

	do {
		fence = dma_fence_get(d->pf.fence);
		if (fence) {
			mutex_unlock(&d->eu_lock);
			dma_fence_wait(fence, true);
			dma_fence_put(fence);
			mutex_lock(&d->eu_lock);
		}
	} while (fence);

	pf_fence = pagefault_fence_create();
	if (!pf_fence)
		goto err_tdctl;

	d->pf.fence = &pf_fence->base;

	INIT_LIST_HEAD(&epf->link);

	if (prelim_xe_gt_eu_attentions_read(gt, &epf->attentions.after,
				     PRELIM_XE_GT_ATTENTION_TIMEOUT_MS))
		goto err_fence;

	xe_force_wake_put(gt_to_fw(gt), fw_ref);

out_set_epf:
	/*
	 * xe_exec_queue_put() will be called from destroy_pagefault()
	 * or handle_pagefault()
	 */
	epf->q = q;
	epf->d = d; /* Ref is taken and will not be dropped here */
	if (!d->pf.first) {
		d->pf.first = epf;
		d->pf.active++;
		d->pf.asid = PF_ASID(pf);
	}
	mutex_unlock(&d->eu_lock);

	epf->lrc_idx = lrc_idx;
	epf->fault.addr = xe_pagefault_addr(pf);
	epf->fault.type_level = pf->consumer.fault_type_level;
	epf->fault.access_type = pf->consumer.access_type;

	/*
	 * VMA is only present on SVM pf and that pf
	 * was early tagged (first pass).
	 * Clear early tag and restore original private
	 * field so it can be safely tagged again.
	 */
	if (vma)
		pf->producer.private =
			prelim_xe_eudebug_pagefault_get_private(pf->producer.private);

	pagefault_set_private(pf, epf);
	epf->svm_vma = vma;

	return 0;

err_fence:
	dma_fence_signal(d->pf.fence);
	dma_fence_put(d->pf.fence);
	d->pf.fence = NULL;
err_tdctl:
	__clear_td_ctl_fee(gt, d);
err_epf:
	kfree(epf);
err_put_fw:
	xe_force_wake_put(gt_to_fw(gt), fw_ref);
err_put_exec_queue_unlock:
	prelim_xe_eudebug_attention_poll_start(gt_to_xe(gt));
	mutex_unlock(&d->eu_lock);
err_put_exec_queue:
	xe_exec_queue_put(q);
err_put_eudebug:
	prelim_xe_eudebug_put(d);

	return -EINVAL;
}

static struct xe_eudebug_pagefault *_get_epf(void *private)
{
	if ((u64)private & PRELIM_XE_EUDEBUG_PAGEFAULT_PRIVATE_EUDEBUG)
		return (struct xe_eudebug_pagefault *)((u64)private &
						       ~PRELIM_XE_EUDEBUG_PAGEFAULT_PRIVATE_EUDEBUG);

	return NULL;

}

static struct xe_eudebug_pagefault *prelim_xe_eudebug_get_epf(struct xe_pagefault *pf)
{
	return _get_epf(pf->producer.private);
}

struct xe_vma *prelim_xe_eudebug_create_vma(struct xe_vm *vm, struct xe_pagefault *pf)
{
	u64 addr;
	size_t align;
	struct xe_vma *vma = NULL;
	struct xe_eudebug_pagefault *epf = prelim_xe_eudebug_get_epf(pf);

	if (!epf)
		return ERR_PTR(-EINVAL);

	align = vm->flags & XE_VM_FLAG_64K ? SZ_64K : SZ_4K;
	addr = ALIGN_DOWN(xe_pagefault_addr(pf), align);
	vma = xe_vm_create_null_vma(vm, addr);
	if (IS_ERR(vma))
		return vma;

	epf->null_vma_addr = xe_vma_start(vma);
	return vma;
}

static void eudebug_destroy_vma(struct xe_vm *vm, struct xe_vma *vma)
{
	struct dma_fence *fence;

	xe_vm_lock(vm, false);
	xe_vm_prep_vma_destroy(vm, vma, true);

	fence = xe_vma_unbind(vm, vma, vma->tile_present);
	if (IS_ERR(fence)) {
		drm_err(&vm->xe->drm,
			"eudebug: failed to unbind temporary NULL vma. Err = %ld\n",
			PTR_ERR(fence));
		fence = NULL;
	} else {
		dma_fence_wait(fence, true);
	}

	xe_vma_destroy(vma, fence);
	if (fence)
		dma_fence_put(fence);
	xe_vm_unlock(vm);
}

static void epf_release_vma(struct xe_eudebug_pagefault *epf)
{
	struct xe_vm *vm = epf_to_vm(epf);
	struct xe_vma *vma;

	if (xe_vm_is_closed(vm)) {
		if (epf->svm_vma) {
			xe_vm_destroy_vma(epf->svm_vma);
			epf->svm_vma = NULL;
		}
		return;
	}

	if (epf->null_vma_addr) {
		u32 psize = vm->flags & XE_VM_FLAG_64K ? SZ_64K : SZ_4K;

		lockdep_assert_held_write(&vm->lock);
		vma = xe_vm_find_vma_by_addr(vm, epf->null_vma_addr);
		/*
		 * VMA must be alive and of NULL type plus
		 * with matching address & size.
		 */
		if (vma &&
		    !(vma->gpuva.flags & XE_VMA_DESTROYED) &&
		    xe_vma_start(vma) == epf->null_vma_addr &&
		    xe_vma_size(vma) == psize &&
		    xe_vma_is_null(vma))
			eudebug_destroy_vma(vm, vma);
		epf->null_vma_addr = 0;
	}

	if (epf->svm_vma) {
		lockdep_assert_held_write(&vm->lock);
		eudebug_try_svm_remap(epf->q->vm, epf->svm_vma);
		epf->svm_vma = NULL;
	}
}

static void destroy_pagefault(struct xe_eudebug_pagefault *epf)
{
	epf_release_vma(epf);

	xe_exec_queue_put(epf->q);
	if (epf->d)
		prelim_xe_eudebug_put(epf->d);
	kfree(epf);
}

static void queue_pagefault(struct xe_eudebug *d,
			    struct xe_eudebug_pagefault *epf)
{
	mutex_lock(&d->pf.lock);
	d = prelim_xe_eudebug_instance_get(d);

	epf_release_vma(epf);

	list_add_tail(&epf->link, &d->pf.pagefaults);

	/* Queued is equivalent of sent. Drop references */
	prelim_xe_eudebug_put(epf->d);
	epf->d = NULL;

	mutex_unlock(&d->pf.lock);
	prelim_xe_eudebug_put(d);
}

static int
xe_eudebug_pagefault_process(struct xe_eudebug_pagefault *epf)
{
	struct xe_gt *gt = epf_to_gt(epf);
	int ret;

	ret = prelim_xe_gt_eu_attentions_read(gt, &epf->attentions.resolved,
				       PRELIM_XE_GT_ATTENTION_TIMEOUT_MS);
	if (ret)
		xe_gt_dbg(gt, "eudbg: resolved attention read failed: %d\n", ret);
	return ret;
}

static int send_queued_pagefaults(struct xe_eudebug *d)
{
	struct xe_eudebug_pagefault *epf, *epf_temp;
	int ret = 0;

	mutex_lock(&d->pf.lock);
	list_for_each_entry_safe(epf, epf_temp, &d->pf.pagefaults, link) {
		ret = prelim_xe_eudebug_send_pagefault_event(d, epf);

		if (ret == -ENOSPC) {
			ret = 0;
			break;
		}

		list_del(&epf->link);

		destroy_pagefault(epf);

		/*
		 * The exec queue went away between this pagefault being
		 * queued and us relaying it. There is nothing to tell the
		 * debugger and nothing wrong with the hardware, so drop it
		 * and keep going. Breaking out here would hand the error to
		 * attention_poll_work(), which treats anything but -EBUSY as
		 * a failure and resets the GT.
		 */
		if (ret == -ENOENT) {
			ret = 0;
			continue;
		}

		if (ret)
			break;
	}
	mutex_unlock(&d->pf.lock);
	return ret;
}

/*
 * Fills up the 'resolved' bitmask.
 * Clears FEE and signlas the pagefault fence.
 * In the end event is send or internally queued.
 *
 * Returns:
 *   0 if epf shall not be destroyed (event was queued).
 *   > 0 if epf shall be destroyed
 *   < 0 on error. -EBUSY requests gt reset.
 *
 */
static int
eudebug_pagefault_finalize(struct xe_eudebug_pagefault *epf, int err)
{
	struct xe_gt *gt = epf_to_gt(epf);
	struct xe_eudebug *d = epf->d;
	unsigned int fw_ref;
	bool queued = false;
	int ret = 0;

	lockdep_assert_held(&d->eu_lock);

	if (!xe_guc_read_stopped(&gt->uc.guc)) {
		fw_ref = xe_force_wake_get(gt_to_fw(gt), epf->q->hwe->domain);
		if (!fw_ref) {
			struct xe_device *xe = gt_to_xe(gt);

			drm_warn(&xe->drm, "Forcewake fail: Can not recover TD_CTL");
			ret = -EBUSY;
		} else {
			ret = __clear_td_ctl_fee(gt, d);
			/* Debug not enabled or FEE Cleared */
			if (ret == -EINVAL || ret == -EOPNOTSUPP)
				ret = 1;
			else if (ret == -ETIMEDOUT)
				ret = -EBUSY;

			xe_force_wake_put(gt_to_fw(gt), fw_ref);
		}
	}

	/* gt was under reset? Skip it. */
	if (ret == -EBUSY &&
	    xe_guc_read_stopped(&gt->uc.guc)) {
		eu_dbg(d, "gt reset under eudebug pagefault processing. Dropping fault\n");
		ret = 1;
	}

	if (!err && !ret && !prelim_xe_eudebug_detached(d)) {
		if (completion_done(&d->discovery)) {
			/* Just in case there was a discovery */
			ret = send_queued_pagefaults(d);
			if (!ret) {
				ret = prelim_xe_eudebug_send_pagefault_event(d, epf);
				if (ret == -ENOSPC) {
					queue_pagefault(d, epf);
					queued = true;
					ret = 0;
				} else if (ret == -ENOENT) {
					/* Queue gone, nothing to relay */
					ret = 0;
				}
			}

		} else {
			queue_pagefault(d, epf);
			queued = true;
		}
	}

	if (d->pf.fence) {
		dma_fence_signal(d->pf.fence);
		dma_fence_put(d->pf.fence);
		d->pf.fence = NULL;
	}

	return ret ? ret : !queued;
}

int prelim_xe_eudebug_handle_pagefaults(struct xe_gt *gt)
{
	struct xe_exec_queue *q;
	struct xe_eudebug *d;
	int ret, lrc_idx;

	q = xe_gt_runalone_active_queue_get(gt, &lrc_idx);
	if (IS_ERR(q))
		return PTR_ERR(q);

	if (!xe_exec_queue_is_debuggable(q)) {
		ret = -EPERM;
		goto out_exec_queue_put;
	}

	d = prelim_xe_eudebug_get_nolock_with_discovery(q->vm->xef);
	if (!d) {
		ret = -ENOTCONN;
		goto out_exec_queue_put;
	} else {
		if (!completion_done(&d->discovery)) {
			prelim_xe_eudebug_put(d);
			ret = -EBUSY;
			goto out_exec_queue_put;
		}
	}

	ret = send_queued_pagefaults(d);

	prelim_xe_eudebug_put(d);

out_exec_queue_put:
	xe_exec_queue_put(q);

	return ret;
}

static bool
xe_eudebug_pagefault_queue_has_asid(struct xe_pagefault_queue *pf_queue,
				    u32 asid)
{
	struct xe_device *xe = container_of(pf_queue, typeof(*xe),
					    usm.pf_queue);
	struct xe_pagefault_work *pf_work;
	struct xe_pagefault *lpf;
	u32 head, tail;
	int i;

	guard(spinlock_irq)(&pf_queue->lock);

	/*
	 * Entry can be as pf_worker.cache but
	 * waiting for eudebug hw mutex.
	 */
	pf_work = xe->usm.pf_workers;
	for (i = 0; i < xe->info.num_pf_work; ++i)
		if (pf_work[i].cache.asid == asid &&
		    pf_work[i].cache.start != XE_PAGEFAULT_CACHE_START_INVALID)
			return true;

	head = pf_queue->head;
	tail = pf_queue->tail;

	/* PF may be queued and pending processing. */
	while (head != tail) {
		lpf = (pf_queue->data + tail);
		if (lpf->consumer.alloc_state == XE_PAGEFAULT_ALLOC_STATE_QUEUED)
			if (PF_ASID(lpf) == asid)
				return true;

		tail = (tail + xe_pagefault_entry_size()) % pf_queue->size;
	}

	return false;
}

static struct xe_eudebug_pagefault *
eudebug_pf_try_tag(void *private, u32 asid)
{
	struct xe_eudebug_pagefault *epf;
	struct xe_guc *guc = private;
	struct xe_device *xe = guc_to_xe(guc);
	struct xe_gt *gt = guc_to_gt(guc);
	struct xe_eudebug *d;
	struct xe_vm *vm;

	if (!prelim_xe_eudebug_is_enabled(xe))
		return NULL;

	vm = xe_device_asid_to_vm(xe, asid);
	if (IS_ERR(vm))
		return NULL;

	d = prelim_xe_eudebug_get_nolock_with_discovery(vm->xef);
	if (!d) {
		xe_vm_put(vm);
		return NULL;
	}

	mutex_lock(&d->xe->eudebug.lock);
	epf = d->pf.first;
	if (epf && asid == d->pf.asid && epf->q->gt == gt)
		d->pf.active++;
	else
		epf = NULL;
	mutex_unlock(&d->xe->eudebug.lock);

	xe_vm_put(vm);
	prelim_xe_eudebug_put(d);

	return epf;
}

void prelim_xe_eudebug_pagefault_end(void *private, u32 asid, int err)
{
	struct xe_eudebug_pagefault *epf = _get_epf(private);
	struct xe_eudebug_pagefault *first_epf = NULL;
	struct xe_pagefault_queue *pf_queue;
	struct xe_device *xe;
	struct xe_eudebug *d;
	struct xe_vm *vm;
	int resume_attn = 0, destroy_pf = 0;

	/*
	 * A resolvable pagefault PF_A can start before unresolvable
	 * PF_B (eudebug) and can land here after PF_B.
	 * In such case PF_B can still see matching ASID (PF_A) in a pf_queue
	 * therefore postpone finalization.
	 * However PF_A, which started before PF_B, will not be tagged
	 * and will passthru here leaving PF_B hanging.
	 *
	 * Set epf, so that the behavior will be similar as if PF_A was
	 * properly tagged.
	 */
	if (!epf) {
		epf = eudebug_pf_try_tag(private, asid);
		if (!epf)
			return;
	}

	xe = gt_to_xe(epf_to_gt(epf));
	pf_queue = &xe->usm.pf_queue;

	d = prelim_xe_eudebug_instance_get(epf->d);
	vm = xe_vm_get(epf_to_vm(epf));
	/* Need to have outer vm lock for eudebug lock as for pagefault start */
	down_write(&vm->lock);
	mutex_lock(&d->eu_lock);
	if (!--d->pf.active) {
		/*
		 * This will also catch entries that are popped from pagefault
		 * queue and moved to worker but not yet processed.
		 * prelim_xe_eudebug_pagefault_start() will catch it later  and increase
		 * the pf.active counter.
		 */
		if (!xe_eudebug_pagefault_queue_has_asid(pf_queue, d->pf.asid)) {
			if (!err && !prelim_xe_eudebug_detached(d))
				err = xe_eudebug_pagefault_process(d->pf.first);

			destroy_pf = eudebug_pagefault_finalize(d->pf.first, err);
			/* If d->pf.first was queued the epf shall be removed. */
			if (epf != d->pf.first) {
				if (destroy_pf)
					first_epf = d->pf.first;
				else
					destroy_pf = 1;
			}
			d->pf.first = NULL;
			d->pf.asid = 0;
			resume_attn = 1;
		} else {
			/* page faults still queued */
			if (epf != d->pf.first)
				destroy_pf = 1;
		}
	} else {
		/* Multiple page faults for different addresses. Remove vma.*/
		if (epf != d->pf.first)
			destroy_pf = 1;
	}
	mutex_unlock(&d->eu_lock);

	if (destroy_pf) {
		struct xe_exec_queue *q = xe_exec_queue_get(epf->q);

		destroy_pagefault(epf);
		if (first_epf)
			destroy_pagefault(first_epf);

		if (unlikely(destroy_pf < 0))
			prelim_xe_eudebug_disconnect(d, destroy_pf);

		/*
		 * EBUSY from eudebug_pagefault_finalize() means HW issue.
		 * GT reset is required. Note that if xe_eudebug_pagefault_finalize()
		 * detects gt reset it will skip tdctl operations and returns
		 * information that epf shall be destroyed.
		 *
		 * Other pagefault may be faster than attention_poll_work()
		 * and hit the same issue. Therefore, reset GT here.
		 */
		if (unlikely(destroy_pf == -EBUSY))
			xe_gt_reset_async(q->gt);

		xe_exec_queue_put(q);
	}
	up_write(&vm->lock);
	xe_vm_put(vm);

	prelim_xe_eudebug_put(d);

	if (resume_attn)
		prelim_xe_eudebug_attention_poll_start(xe);
}

void prelim_xe_eudebug_pagefault_fini(struct xe_eudebug *d)
{
	struct xe_eudebug_pagefault *epf, *epf_temp;

	/* Since it's the last reference no race here */

	list_for_each_entry_safe(epf, epf_temp, &d->pf.pagefaults, link) {
		list_del(&epf->link);
		destroy_pagefault(epf);
	}

	/*
	 * Since we're called from xe_eudebug_free() there shall be
	 * no d->pf.first since d->pf.first has a reference to d.
	 * So free is not expected unless there is error somewhere.
	 * Reference to d is dropped in queue_pagefault().
	 */
	if (XE_WARN_ON(d->pf.first)) {
		struct xe_vm *vm;

		epf = d->pf.first;
		epf->d = NULL; /* prevent underflow */
		vm = xe_vm_get(epf_to_vm(epf));
		down_write(&vm->lock);
		destroy_pagefault(epf);
		up_write(&vm->lock);
		xe_vm_put(vm);
	}
}

void prelim_xe_eudebug_pagefault_signal(struct xe_eudebug *d)
{
	struct dma_fence *f;

	mutex_lock(&d->eu_lock);
	f = d->pf.fence;
	d->pf.fence = NULL;
	mutex_unlock(&d->eu_lock);

	if (f) {
		dma_fence_signal(f);
		dma_fence_put(f);
	}
}

static void eudebug_pagefault_gt_reset_work(struct work_struct *work)
{
	struct xe_gt *gt = container_of(work, typeof(*gt),
					eudebug.gt_reset_work);
	struct xe_eudebug_pagefault *epf = NULL;
	struct xe_device *xe = gt_to_xe(gt);
	struct xe_eudebug *d = NULL;
	struct xe_vm *vm;
	unsigned long i;

	/*
	 * Search for deferred abandoned eudebug pagefault.
	 * xe_pagefault_queue_reset() drops QUEUED entries but
	 * not the ACTIVE ones which are already in some worker.
	 * If there are any d->pf.active it means some worker
	 * will reach eudebug_pagefault_end() and clear
	 * d->pf.first.
	 * If there is no active and there if first the
	 * pagefault was deferred but now queue is cleared
	 * and no one will reach the first now.
	 */

	down_read(&xe->usm.lock);
	xa_for_each(&xe->usm.asid_to_vm, i, vm) {
		vm = xe_vm_get(vm);

		d = prelim_xe_eudebug_get_nolock_with_discovery(vm->xef);
		if (!d) {
			xe_vm_put(vm);
			continue;
		}

		down_write(&vm->lock);
		mutex_lock(&xe->eudebug.lock);
		if (!d->pf.active && d->pf.first &&
		    d->pf.first->q->gt == gt &&
		    d->pf.first->q->vm == vm) {

			epf = d->pf.first;

			d->pf.first = NULL;
			d->pf.asid = 0;

			if (d->pf.fence) {
				dma_fence_signal(d->pf.fence);
				dma_fence_put(d->pf.fence);
				d->pf.fence = NULL;
			}
		}
		mutex_unlock(&xe->eudebug.lock);
		up_write(&vm->lock);

		if (epf)
			break;

		xe_vm_put(vm);
		prelim_xe_eudebug_put(d);
	}
	up_read(&xe->usm.lock);

	if (epf) {
		eu_dbg(d, "pagefault 0x%016llx canceled due to GT reset\n",
		       epf->fault.addr);
		xe_pm_runtime_get(xe);
		down_write(&vm->lock);
		destroy_pagefault(epf);
		up_write(&vm->lock);
		xe_pm_runtime_put(xe);
		xe_vm_put(vm);
		prelim_xe_eudebug_disconnect(d, -EAGAIN);
		prelim_xe_eudebug_put(d);
		prelim_xe_eudebug_attention_poll_start(xe);
	}
}

void prelim_xe_eudebug_pagefault_gt_init(struct xe_gt *gt)
{
	INIT_WORK(&gt->eudebug.gt_reset_work,
		  eudebug_pagefault_gt_reset_work);
}

void prelim_xe_eudebug_pagefault_reset(struct xe_device *xe,
				struct xe_gt *gt)
{
	if (!prelim_xe_eudebug_is_enabled(xe))
		return;

	queue_work(xe->eudebug.pagefault_reset_wq, &gt->eudebug.gt_reset_work);
}

bool prelim_xe_eudebug_pagefault_creatable(struct xe_gt *gt, struct xe_vm *vm)
{
	struct xe_exec_queue *q;
	struct xe_eudebug *d;
	bool ret = false;
	int lrc_idx;

	if (GRAPHICS_VER(gt_to_xe(gt)) >= 35)
		goto out;

	d = prelim_xe_eudebug_get_nolock_with_discovery(vm->xef);
	if (!d)
		goto out;

	q = xe_gt_runalone_active_queue_get(gt, &lrc_idx);
	if (IS_ERR(q))
		goto err_put_eudebug;

	if (XE_WARN_ON(q->vm != vm))
		goto err_put_exec_queue;

	if (!xe_exec_queue_is_debuggable(q))
		goto err_put_exec_queue;

	ret = true;

err_put_exec_queue:
	xe_exec_queue_put(q);
err_put_eudebug:
	prelim_xe_eudebug_put(d);

out:
	return ret;
}
