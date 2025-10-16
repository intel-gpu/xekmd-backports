dnl #
dnl # v6.9-9ca5facd0400f
dnl # lib/string_choices: Add str_plural() helper
dnl #
AC_DEFUN([AC_STR_PLURAL_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/string_choices.h>
                ],[
                        str_plural(0);
                ],[
		],[
                        AC_DEFINE(BPM_STR_PLURAL_NOT_PRESENT, 1,
                                [str_plural() is not available])
                ])
        ])
])

dnl #
dnl # v6.12-a98ae7f045b2
dnl # lib/string_choices: Add str_up_down() helper
dnl #
AC_DEFUN([AC_STR_UP_DOWN_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/string_choices.h>
		],[
			str_up_down(0);
		],[
		],[
			AC_DEFINE(BPM_STR_UP_DOWN_NOT_PRESENT, 1,
				[str_up_down() is not available])
		])
	])
])
