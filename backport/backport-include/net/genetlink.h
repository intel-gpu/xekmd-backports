#ifndef __BACKPORT_NET_GENETLINK_H
#define __BACKPORT_NET_GENETLINK_H

#include_next <net/genetlink.h>

#ifdef BPM_GENL_REQ_ATTR_CHECK_NOT_PRESENT

#ifndef GENL_REQ_ATTR_CHECK
#define GENL_REQ_ATTR_CHECK(info, attr) ({			\
	const struct genl_info *__info = (info);		\
								\
	NL_REQ_ATTR_CHECK(__info->extack, NULL, __info->attrs, (attr)); \
})
#endif

#endif /* BPM_GENL_REQ_ATTR_CHECK_NOT_PRESENT */

#endif /* __BACKPORT_NET_GENETLINK_H */
