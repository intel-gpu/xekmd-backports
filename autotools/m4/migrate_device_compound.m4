dnl #
dnl # a30b48bf1b2
dnl # mm/migrate_device: implement THP migration of zone device pages
dnl #

AC_DEFUN([AC_MIGRATE_VMA_SELECT_COMPOUND_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/migrate.h>
                ],[
                        MIGRATE_VMA_SELECT_COMPOUND;
                        MIGRATE_PFN_COMPOUND;
                ],[
                ],[
                        AC_DEFINE(BPM_MIGRATE_VMA_SELECT_COMPOUND_NOT_PRESENT, 1,
                                [MIGRATE_VMA_SELECT_COMPOUND and MIGRATE_PFN_COMPOUND not present])
                ])
        ])
])
