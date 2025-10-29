#ifndef _COMPAT_LINUX_EXPORT_H
#define _COMPAT_LINUX_EXPORT_H 1

#include <linux/version.h>

#include_next <linux/export.h>

#ifdef BPM_MODULE_IMPORT_TO_STRING_LITERAL_PRESENT
#undef EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns) __EXPORT_SYMBOL(sym, "GPL", ns)
#endif

#ifndef EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns) EXPORT_SYMBOL_GPL(sym)
#endif

#endif /* _COMPAT_LINUX_EXPORT_H */
