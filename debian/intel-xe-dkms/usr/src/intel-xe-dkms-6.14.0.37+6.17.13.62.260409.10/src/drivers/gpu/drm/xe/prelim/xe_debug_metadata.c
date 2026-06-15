// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */
#include "xe_debug_metadata.h"

#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <uapi/drm/xe_drm.h>

#include "xe_device.h"
#include "prelim/xe_eudebug.h"
#include "xe_macros.h"
#include "xe_vm.h"

void xe_eudebug_free_vma_metadata(struct xe_eudebug_vma_metadata *mdata)
{
	struct xe_vma_debug_metadata *vmad, *tmp;

	list_for_each_entry_safe(vmad, tmp, &mdata->list, link) {
		list_del(&vmad->link);
		kfree(vmad);
	}
}

static struct xe_vma_debug_metadata *
vma_new_debug_metadata(u32 metadata_id, u64 cookie)
{
	struct xe_vma_debug_metadata *vmad;

	vmad = kzalloc(sizeof(*vmad), GFP_KERNEL);
	if (!vmad)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&vmad->link);

	vmad->metadata_id = metadata_id;
	vmad->cookie = cookie;

	return vmad;
}

int xe_eudebug_copy_vma_metadata(struct xe_eudebug_vma_metadata *from,
				 struct xe_eudebug_vma_metadata *to)
{
	struct xe_vma_debug_metadata *vmad, *vma;

	list_for_each_entry(vmad, &from->list, link) {
		vma = vma_new_debug_metadata(vmad->metadata_id, vmad->cookie);
		if (IS_ERR(vma))
			return PTR_ERR(vma);

		list_add_tail(&vmad->link, &to->list);
	}

	return 0;
}

static int vma_new_debug_metadata_op(struct xe_vma_op *op,
				     u32 metadata_id, u64 cookie,
				     u64 flags)
{
	struct xe_vma_debug_metadata *vmad;

	vmad = vma_new_debug_metadata(metadata_id, cookie);
	if (IS_ERR(vmad))
		return PTR_ERR(vmad);

	list_add_tail(&vmad->link, &op->map.eudebug.metadata.list);

	return 0;
}

int vm_bind_op_ext_attach_debug(struct xe_device *xe,
				struct xe_file *xef,
				struct drm_gpuva_ops *ops,
				u32 operation, u64 extension)
{
	u64 __user *address = u64_to_user_ptr(extension);
	struct prelim_drm_xe_vm_bind_op_ext_attach_debug ext;
	struct prelim_xe_debug_metadata *mdata;
	struct drm_gpuva_op *__op;
	int err;

	err = __copy_from_user(&ext, address, sizeof(ext));
	if (XE_IOCTL_DBG(xe, err))
		return -EFAULT;

	if (XE_IOCTL_DBG(xe,
			 operation != DRM_XE_VM_BIND_OP_MAP_USERPTR &&
			 operation != DRM_XE_VM_BIND_OP_MAP))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, ext.flags))
		return -EINVAL;

	mdata = prelim_xe_debug_metadata_get(xef, (u32)ext.metadata_id);
	if (XE_IOCTL_DBG(xe, !mdata))
		return -ENOENT;

	/* care about metadata existence only on the time of attach */
	prelim_xe_debug_metadata_put(mdata);

	if (!ops)
		return 0;

	drm_gpuva_for_each_op(__op, ops) {
		struct xe_vma_op *op = gpuva_op_to_vma_op(__op);

		if (op->base.op == DRM_GPUVA_OP_MAP) {
			err = vma_new_debug_metadata_op(op,
							ext.metadata_id,
							ext.cookie,
							ext.flags);
			if (err)
				return err;
		}
	}
	return 0;
}

static void prelim_xe_debug_metadata_release(struct kref *ref)
{
	struct prelim_xe_debug_metadata *mdata = container_of(ref, struct prelim_xe_debug_metadata, refcount);

	kvfree(mdata->ptr);
	kfree(mdata);
}

void prelim_xe_debug_metadata_put(struct prelim_xe_debug_metadata *mdata)
{
	kref_put(&mdata->refcount, prelim_xe_debug_metadata_release);
}

struct prelim_xe_debug_metadata *prelim_xe_debug_metadata_get(struct xe_file *xef, u32 id)
{
	struct prelim_xe_debug_metadata *mdata;

	mutex_lock(&xef->eudebug.metadata.lock);
	mdata = xa_load(&xef->eudebug.metadata.xa, id);
	if (mdata)
		kref_get(&mdata->refcount);
	mutex_unlock(&xef->eudebug.metadata.lock);

	return mdata;
}

int prelim_xe_debug_metadata_create_ioctl(struct drm_device *dev,
				   void *data,
				   struct drm_file *file)
{
	struct xe_device *xe = to_xe_device(dev);
	struct xe_file *xef = to_xe_file(file);
	struct prelim_drm_xe_debug_metadata_create *args = data;
	struct prelim_xe_debug_metadata *mdata;
	int err;
	u32 id;

	if (XE_IOCTL_DBG(xe, args->extensions))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, args->type >= PRELIM_WORK_IN_PROGRESS_DRM_XE_DEBUG_METADATA_NUM))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, !args->user_addr || !args->len))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, !access_ok(u64_to_user_ptr(args->user_addr), args->len)))
		return -EFAULT;

	mdata = kzalloc(sizeof(*mdata), GFP_KERNEL);
	if (!mdata)
		return -ENOMEM;

	mdata->len = args->len;
	mdata->type = args->type;

	mdata->ptr = kvmalloc(mdata->len, GFP_KERNEL);
	if (!mdata->ptr) {
		kfree(mdata);
		return -ENOMEM;
	}
	kref_init(&mdata->refcount);

	err = copy_from_user(mdata->ptr, u64_to_user_ptr(args->user_addr), mdata->len);
	if (err) {
		err = -EFAULT;
		goto put_mdata;
	}

	mutex_lock(&xef->eudebug.metadata.lock);
	err = xa_alloc(&xef->eudebug.metadata.xa, &id, mdata, xa_limit_32b, GFP_KERNEL);
	mutex_unlock(&xef->eudebug.metadata.lock);

	if (err)
		goto put_mdata;

	args->metadata_id = id;

	prelim_xe_eudebug_debug_metadata_create(xef, mdata);

	return 0;

put_mdata:
	prelim_xe_debug_metadata_put(mdata);
	return err;
}

int prelim_xe_debug_metadata_destroy_ioctl(struct drm_device *dev,
				    void *data,
				    struct drm_file *file)
{
	struct xe_device *xe = to_xe_device(dev);
	struct xe_file *xef = to_xe_file(file);
	struct prelim_drm_xe_debug_metadata_destroy * const args = data;
	struct prelim_xe_debug_metadata *mdata;

	if (XE_IOCTL_DBG(xe, args->extensions))
		return -EINVAL;

	mutex_lock(&xef->eudebug.metadata.lock);
	mdata = xa_erase(&xef->eudebug.metadata.xa, args->metadata_id);
	mutex_unlock(&xef->eudebug.metadata.lock);
	if (XE_IOCTL_DBG(xe, !mdata))
		return -ENOENT;

	prelim_xe_eudebug_debug_metadata_destroy(xef, mdata);

	prelim_xe_debug_metadata_put(mdata);

	return 0;
}
