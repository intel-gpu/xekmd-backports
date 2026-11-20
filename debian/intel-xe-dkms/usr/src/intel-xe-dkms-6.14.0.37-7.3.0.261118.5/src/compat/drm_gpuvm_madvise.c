// SPDX-License-Identifier: GPL-2.0-only

#include <linux/slab.h>
#include <drm/drm_gpuvm.h>
#include <drm/drm_gem.h>

#ifdef BPM_DRM_GPUVM_MADVISE_OPS_CREATE_NOT_PRESENT

static int
madvise_step(struct drm_gpuvm *gpuvm, struct drm_gpuva_ops *ops,
	     const struct drm_gpuva_op *__op)
{
	const struct drm_gpuvm_ops *fn = gpuvm->ops;
	struct drm_gpuva_op *op;

	if (fn && fn->op_alloc)
		op = fn->op_alloc();
	else
		op = kzalloc(sizeof(*op), GFP_KERNEL);

	if (unlikely(!op))
		return -ENOMEM;

	memcpy(op, __op, sizeof(*op));

	if (op->op == DRM_GPUVA_OP_REMAP) {
		const struct drm_gpuva_op_remap *__r = &__op->remap;
		struct drm_gpuva_op_remap *r = &op->remap;

		r->prev = NULL;
		r->next = NULL;

		r->unmap = kmemdup(__r->unmap, sizeof(*r->unmap), GFP_KERNEL);
		if (unlikely(!r->unmap))
			goto err_free_op;

		if (__r->prev) {
			r->prev = kmemdup(__r->prev, sizeof(*r->prev),
					  GFP_KERNEL);
			if (unlikely(!r->prev))
				goto err_free_unmap;
		}

		if (__r->next) {
			r->next = kmemdup(__r->next, sizeof(*r->next),
					  GFP_KERNEL);
			if (unlikely(!r->next))
				goto err_free_prev;
		}
	}

	list_add_tail(&op->entry, &ops->list);

	return 0;

err_free_prev:
	kfree(op->remap.prev);
err_free_unmap:
	kfree(op->remap.unmap);
err_free_op:
	if (fn && fn->op_free)
		fn->op_free(op);
	else
		kfree(op);
	return -ENOMEM;
}

static int
madvise_map(struct drm_gpuvm *gpuvm, struct drm_gpuva_ops *ops,
	    const struct drm_gpuvm_map_req *req)
{
	struct drm_gpuva_op op = {};

	if (!req)
		return 0;

	op.op = DRM_GPUVA_OP_MAP;
	op.map.va.addr = req->map.va.addr;
	op.map.va.range = req->map.va.range;
	op.map.gem.obj = req->map.gem.obj;
	op.map.gem.offset = req->map.gem.offset;

	return madvise_step(gpuvm, ops, &op);
}

static int
madvise_remap(struct drm_gpuvm *gpuvm, struct drm_gpuva_ops *ops,
	      struct drm_gpuva_op_map *prev, struct drm_gpuva_op_map *next,
	      struct drm_gpuva_op_unmap *unmap)
{
	struct drm_gpuva_op op = {};

	op.op = DRM_GPUVA_OP_REMAP;
	op.remap.prev = prev;
	op.remap.next = next;
	op.remap.unmap = unmap;

	return madvise_step(gpuvm, ops, &op);
}

static int
madvise_split(struct drm_gpuvm *gpuvm, struct drm_gpuva_ops *ops,
	      const struct drm_gpuvm_map_req *req)
{
	const struct drm_gpuvm_map_req *op_map = NULL;
	struct drm_gpuva *va, *next;
	u64 req_range = req->map.va.range;
	u64 req_addr = req->map.va.addr;
	u64 req_end = req_addr + req_range;
	int ret;

	if (unlikely(!drm_gpuvm_range_valid(gpuvm, req_addr, req_range)))
		return -EINVAL;

	drm_gpuvm_for_each_va_range_safe(va, next, gpuvm, req_addr, req_end) {
		struct drm_gem_object *obj = va->gem.obj;
		u64 offset = va->gem.offset;
		u64 addr = va->va.addr;
		u64 range = va->va.range;
		u64 end = addr + range;
		struct drm_gpuva_op_unmap u = { .va = va };

		/* madvise only splits VAs that are not backed by a GEM object */
		if (obj)
			continue;

		if (addr == req_addr) {
			if (end == req_end)
				break;

			if (end < req_end)
				continue;

			if (end > req_end) {
				struct drm_gpuva_op_map n = {
					.va.addr = req_end,
					.va.range = range - req_range,
					.gem.obj = obj,
					.gem.offset = offset + req_range,
				};

				ret = madvise_remap(gpuvm, ops, NULL, &n, &u);
				if (ret)
					return ret;

				op_map = req;
				break;
			}
		} else if (addr < req_addr) {
			u64 ls_range = req_addr - addr;
			struct drm_gpuva_op_map p = {
				.va.addr = addr,
				.va.range = ls_range,
				.gem.obj = obj,
				.gem.offset = offset,
			};

			if (end == req_end) {
				ret = madvise_remap(gpuvm, ops, &p, NULL, &u);
				if (ret)
					return ret;

				op_map = req;
				break;
			}

			if (end < req_end) {
				struct drm_gpuvm_map_req map_req = {
					.map.va.addr = req_addr,
					.map.va.range = end - req_addr,
				};

				ret = madvise_remap(gpuvm, ops, &p, NULL, &u);
				if (ret)
					return ret;

				ret = madvise_map(gpuvm, ops, &map_req);
				if (ret)
					return ret;

				continue;
			}

			if (end > req_end) {
				struct drm_gpuva_op_map n = {
					.va.addr = req_end,
					.va.range = end - req_end,
					.gem.obj = obj,
					.gem.offset = offset + ls_range +
						      req_range,
				};

				ret = madvise_remap(gpuvm, ops, &p, &n, &u);
				if (ret)
					return ret;

				op_map = req;
				break;
			}
		} else if (addr > req_addr) {
			if (end == req_end)
				break;

			if (end < req_end)
				continue;

			if (end > req_end) {
				struct drm_gpuva_op_map n = {
					.va.addr = req_end,
					.va.range = end - req_end,
					.gem.obj = obj,
					.gem.offset = offset + req_end - addr,
				};
				struct drm_gpuvm_map_req map_req = {
					.map.va.addr = addr,
					.map.va.range = req_end - addr,
				};

				ret = madvise_remap(gpuvm, ops, NULL, &n, &u);
				if (ret)
					return ret;

				return madvise_map(gpuvm, ops, &map_req);
			}
		}
	}

	return madvise_map(gpuvm, ops, op_map);
}

/**
 * drm_gpuvm_madvise_ops_create() - creates the &drm_gpuva_ops to split
 * @gpuvm: the &drm_gpuvm representing the GPU VA space
 * @req: map request arguments
 *
 * This function creates a list of operations to perform splitting
 * of existent mapping(s) at start or end, based on the request map.
 *
 * Compatibility implementation for kernels whose drm_gpuvm does not provide
 * drm_gpuvm_madvise_ops_create().
 *
 * There will be no unmap operations, a maximum of two remap operations and two
 * map operations. The two map operations correspond to: one from start to the
 * end of drm_gpuvaX, and another from the start of drm_gpuvaY to end.
 *
 * Returns: a pointer to the &drm_gpuva_ops on success, an ERR_PTR on failure
 */
struct drm_gpuva_ops *
drm_gpuvm_madvise_ops_create(struct drm_gpuvm *gpuvm,
			     const struct drm_gpuvm_map_req *req)
{
	struct drm_gpuva_ops *ops;
	int ret;

	ops = kzalloc(sizeof(*ops), GFP_KERNEL);
	if (unlikely(!ops))
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&ops->list);

	ret = madvise_split(gpuvm, ops, req);
	if (ret) {
		drm_gpuva_ops_free(gpuvm, ops);
		return ERR_PTR(ret);
	}

	return ops;
}
EXPORT_SYMBOL_GPL(drm_gpuvm_madvise_ops_create);
#endif
