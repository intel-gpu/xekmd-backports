#ifndef _COMPAT_LINUX_EXPORT_H
#define _COMPAT_LINUX_EXPORT_H 1

#include <linux/version.h>

#include_next <linux/export.h>

#ifdef BPM_MODULE_IMPORT_TO_STRING_LITERAL_PRESENT
#undef EXPORT_SYMBOL_NS_GPL
#ifdef __EXPORT_SYMBOL_REF
#define EXPORT_SYMBOL_NS_GPL(sym, ns) __EXPORT_SYMBOL(sym, "GPL", ns)
#else
#define EXPORT_SYMBOL_NS_GPL(sym, ns) __EXPORT_SYMBOL(sym, "_gpl", ns)
#endif
#endif

#ifndef EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns) EXPORT_SYMBOL_GPL(sym)
#endif

#ifdef BPM_EXPORT_SYMBOL_FOR_MODULES_NOT_PRESENT
#undef EXPORT_SYMBOL_FOR_MODULES
#ifdef __EXPORT_SYMBOL_REF
#define EXPORT_SYMBOL_FOR_MODULES(sym, mods) __EXPORT_SYMBOL(sym, "GPL", mods)
#else
#define EXPORT_SYMBOL_FOR_MODULES(sym, mods) __EXPORT_SYMBOL(sym, "_gpl", mods)
#endif
#endif

#endif /* _COMPAT_LINUX_EXPORT_H */
