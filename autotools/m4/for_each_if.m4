dnl for_each_if.m4 - check for for_each_if in linux/util_macros.h
AC_DEFUN([AC_FOR_EACH_IF_NOT_PRESENT], [
AC_KERNEL_DO_BACKGROUND([
AC_KERNEL_TRY_COMPILE([
#include <linux/util_macros.h>
], [
int x = 1;
for_each_if(x) { }
], [
AC_MSG_RESULT(yes)
], [
AC_DEFINE(BPM_FOR_EACH_IF_NOT_PRESENT, 1,
[for_each_if is not in linux/util_macros.h])
AC_MSG_RESULT(no)
])
])
])
