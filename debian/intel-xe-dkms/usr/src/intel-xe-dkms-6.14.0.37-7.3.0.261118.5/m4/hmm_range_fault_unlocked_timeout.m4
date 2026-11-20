dnl #
dnl #  v7.3 - 121170831228
dnl #  mm/hmm: add hmm_range_fault_unlocked_timeout() for mmap lock-drop support
dnl #

AC_DEFUN([AC_HMM_RANGE_FAULT_UNLOCKED_TIMEOUT_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/hmm.h>
		], [
			struct hmm_range range = { 0 };

			(void)hmm_range_fault_unlocked_timeout(&range, 1);
		], [
		], [
			AC_DEFINE(BPM_HMM_RANGE_FAULT_UNLOCKED_TIMEOUT_NOT_PRESENT, 1,
				  [hmm_range_fault_unlocked_timeout() is not available])
		])
	])
])
