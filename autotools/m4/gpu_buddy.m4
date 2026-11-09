dnl #
dnl # v6.12-b2c30f2e4e53
dnl # gpu buddy allocator moved under linux/gpu_buddy.h
dnl #
AC_DEFUN([AC_LINUX_GPU_BUDDY_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/gpu_buddy.h>
		],[
			struct gpu_buddy *mm = NULL;
			gpu_buddy_alloc_blocks(mm, 0, 0, 0, 0, NULL, 0);
		],[
		],[
			AC_DEFINE(BPM_LINUX_GPU_BUDDY_NOT_PRESENT, 1,
				[linux/gpu_buddy.h is not available])
		])
	])
])

dnl #
dnl # v6.12-151ebbc20aa2
dnl # drm/gpu: Add gpu_buddy_allocated_addr_to_block helper
dnl # 
AC_DEFUN([AC_GPU_BUDDY_ALLOCATED_ADDR_TO_BLOCK_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/gpu_buddy.h>
		],[
			struct gpu_buddy *mm = NULL;
			gpu_buddy_allocated_addr_to_block(mm, 0);
		],[
		],[
			AC_DEFINE(BPM_GPU_BUDDY_ALLOCATED_ADDR_TO_BLOCK_NOT_PRESENT, 1,
				[gpu_buddy_allocated_addr_to_block() is not available])
		])
	])
])
