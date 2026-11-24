dnl #
dnl # d245f9b4ab80
dnl # mm/zone_device: support large zone device private folios

AC_DEFUN([AC_ZONE_DEVICE_FOLIO_INIT_NOT_PRESENT], [
               AC_KERNEL_DO_BACKGROUND([
                       AC_KERNEL_TRY_COMPILE([
                               #include <linux/memremap.h>
                       ],[
                               zone_device_folio_init(NULL, NULL);
                       ],[
                       ],[
                               AC_DEFINE(BPM_ZONE_DEVICE_FOLIO_INIT_NOT_PRESENT, 1,
                                       [zone_device_folio_init() is not available, use page concept])
                       ])
               ])
])
