#ifndef __BACKPORT_LINUX_NETLINK_H
#define __BACKPORT_LINUX_NETLINK_H

#include_next <linux/netlink.h>

#ifdef BPM_GENL_REQ_ATTR_CHECK_NOT_PRESENT

#ifndef NL_SET_ERR_ATTR_MISS
#define NL_SET_ERR_ATTR_MISS(extack, nest, type) do { } while (0)
#endif

#ifndef NL_REQ_ATTR_CHECK
#define NL_REQ_ATTR_CHECK(extack, nest, tb, type) ({	\
	struct nlattr **__tb = (tb);			\
	u32 __attr = (type);				\
	int __retval;					\
							\
	__retval = !__tb[__attr];			\
	if (__retval)					\
		NL_SET_ERR_ATTR_MISS((extack), (nest), __attr); \
	__retval;					\
})
#endif

#endif /* BPM_GENL_REQ_ATTR_CHECK_NOT_PRESENT */

#endif /* __BACKPORT_LINUX_NETLINK_H */
