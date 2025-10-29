dnl #
dnl # v6.14-94a20fb9af16
dnl # sysfs: treewide: constify attribute callback of bin_attribute::mmap()
dnl #
AC_DEFUN([AC_CONST_STRUCT_BIN_ATTRIBUTE_IS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/sysfs.h>
		],[
			int test_mmap(struct file *filp, struct kobject *kobj,
				      const struct bin_attribute *attr,
				      struct vm_area_struct *vma) { return 0; }
			
			struct bin_attribute test_attr = {
				.mmap = test_mmap,
			};
		],[
		],[
			AC_DEFINE(BPM_CONST_STRUCT_BIN_ATTRIBUTE_IS_NOT_PRESENT, 1,
				[bin_attribute callbacks do not expect const parameter])
		])
	])
])

dnl #
dnl # v6.14-7ff2fecc8bc2
dnl # platform/x86/intel/pmt: Constify 'struct bin_attribute'
dnl #
AC_DEFUN([AC_STRUCT_BIN_ATTRIBUTE_READ_NEW_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/sysfs.h>
                ],[
                        struct bin_attribute test_attr;
                        test_attr.read_new = NULL;
                ],[
                ],[
                        AC_DEFINE(BPM_STRUCT_BIN_ATTRIBUTE_READ_NEW_NOT_PRESENT, 1,
                                [struct bin_attribute does not have read_new member])
                ])
        ])
])
