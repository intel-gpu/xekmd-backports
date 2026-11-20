dnl #
dnl #  v6.19 - a30b48bf1b24
dnl #  mm/migrate_device: implement THP migration of zone device pages
dnl #

AC_DEFUN([AC_MIGRATE_VMA_SELECT_COMPOUND_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/migrate.h>
                ],[
                        unsigned long test = MIGRATE_VMA_SELECT_COMPOUND |
                                             MIGRATE_PFN_COMPOUND;
                        (void)test;
                ],[
                ],[
                        AC_DEFINE(BPM_MIGRATE_VMA_SELECT_COMPOUND_NOT_PRESENT, 1,
                                [Compound migration flags are unavailable])
                ])
        ])
])
