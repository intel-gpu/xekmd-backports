dnl #
dnl # v6.4-7b806d229ef1
dnl # mm: remove vmf_insert_pfn_xxx_prot() for huge page-table entries
dnl #
AC_DEFUN([AC_VMF_INSERT_PFN_ARG_PFN_T_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/mm.h>
                ],[
                        struct vm_fault *vmf = NULL;
                        unsigned long pfn = 0;
                        vmf_insert_pfn_pmd(vmf, pfn, false);
                ],[
                ],[
                        AC_DEFINE(BPM_VMF_INSERT_PFN_ARG_PFN_T_NOT_PRESENT, 1,
                                [vmf_insert_pfn_pmd()/vmf_insert_pfn_pud() expect pfn_t argument])
                ])
        ])
])
