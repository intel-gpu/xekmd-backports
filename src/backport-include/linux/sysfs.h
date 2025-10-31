#ifndef __BACKPORT_LINUX_SYSFS_H
#define __BACKPORT_LINUX_SYSFS_H
#include_next <linux/sysfs.h>
#include <linux/version.h>

#ifndef __ATTR_RW
#define __ATTR_RW(_name) __ATTR(_name, (S_IWUSR | S_IRUGO),		\
			 _name##_show, _name##_store)
#endif

#if LINUX_VERSION_IS_LESS(5,10,0)
#define sysfs_emit LINUX_BACKPORT(sysfs_emit)
#define sysfs_emit_at LINUX_BACKPORT(sysfs_emit_at)
#ifdef CONFIG_SYSFS
__printf(2, 3)
int sysfs_emit(char *buf, const char *fmt, ...);
__printf(3, 4)
int sysfs_emit_at(char *buf, int at, const char *fmt, ...);
#else /* CONFIG_SYSFS */
__printf(2, 3)
static inline int sysfs_emit(char *buf, const char *fmt, ...)
{
	return 0;
}

__printf(3, 4)
static inline int sysfs_emit_at(char *buf, int at, const char *fmt, ...)
{
	retur 0;
}
#endif /* CONFIG_SYSFS */
#endif /* < 5.10 */

#ifndef __ATTR_RW_MODE
#define __ATTR_RW_MODE(_name, _mode) {					\
	.attr	= { .name = __stringify(_name),				\
		    .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _name##_show,						\
	.store	= _name##_store,					\
}
#endif

#ifdef BPM_DEFINE_SYSFS_GROUP_VISIBLE_NOT_PRESENT
#define SYSFS_GROUP_INVISIBLE   020000

/*
 * DEFINE_SYSFS_GROUP_VISIBLE(name):
 *      A helper macro to pair with the assignment of ".is_visible =
 *      SYSFS_GROUP_VISIBLE(name)", that arranges for the directory
 *      associated with a named attribute_group to optionally be hidden.
 *      This allows for static declaration of attribute_groups, and the
 *      simplification of attribute visibility lifetime that implies,
 *      without polluting sysfs with empty attribute directories.
 * Ex.
 *
 * static umode_t example_attr_visible(struct kobject *kobj,
 *                                   struct attribute *attr, int n)
 * {
 *       if (example_attr_condition)
 *               return 0;
 *       else if (ro_attr_condition)
 *               return 0444;
 *       return a->mode;
 * }
 *
 * static bool example_group_visible(struct kobject *kobj)
 * {
 *       if (example_group_condition)
 *               return false;
 *       return true;
 * }
 *
 * DEFINE_SYSFS_GROUP_VISIBLE(example);
 *
 * static struct attribute_group example_group = {
 *       .name = "example",
 *       .is_visible = SYSFS_GROUP_VISIBLE(example),
 *       .attrs = &example_attrs,
 * };
 *
 * Note that it expects <name>_attr_visible and <name>_group_visible to
 * be defined. For cases where individual attributes do not need
 * separate visibility consideration, only entire group visibility at
 * once, see DEFINE_SIMPLE_SYSFS_GROUP_VISIBLE().
 */
#define DEFINE_SYSFS_GROUP_VISIBLE(name)                             \
        static inline umode_t sysfs_group_visible_##name(            \
                struct kobject *kobj, struct attribute *attr, int n) \
        {                                                            \
                if (n == 0 && !name##_group_visible(kobj))           \
                        return SYSFS_GROUP_INVISIBLE;                \
                return name##_attr_visible(kobj, attr, n);           \
        }

/*
 * DEFINE_SIMPLE_SYSFS_GROUP_VISIBLE(name):
 *      A helper macro to pair with SYSFS_GROUP_VISIBLE() that like
 *      DEFINE_SYSFS_GROUP_VISIBLE() controls group visibility, but does
 *      not require the implementation of a per-attribute visibility
 *      callback.
 * Ex.
 *
 * static bool example_group_visible(struct kobject *kobj)
 * {
 *       if (example_group_condition)
 *               return false;
 *       return true;
 * }
 *
 * DEFINE_SIMPLE_SYSFS_GROUP_VISIBLE(example);
 *
 * static struct attribute_group example_group = {
 *       .name = "example",
 *       .is_visible = SYSFS_GROUP_VISIBLE(example),
 *       .attrs = &example_attrs,
 * };
 */
#define DEFINE_SIMPLE_SYSFS_GROUP_VISIBLE(name)                   \
        static inline umode_t sysfs_group_visible_##name(         \
                struct kobject *kobj, struct attribute *a, int n) \
        {                                                         \
                if (n == 0 && !name##_group_visible(kobj))        \
                        return SYSFS_GROUP_INVISIBLE;             \
                return a->mode;                                   \
        }

/*
 * Same as DEFINE_SYSFS_GROUP_VISIBLE, but for groups with only binary
 * attributes. If an attribute_group defines both text and binary
 * attributes, the group visibility is determined by the function
 * specified to is_visible() not is_bin_visible()
 */
#define DEFINE_SYSFS_BIN_GROUP_VISIBLE(name)                             \
        static inline umode_t sysfs_group_visible_##name(                \
                struct kobject *kobj, struct bin_attribute *attr, int n) \
        {                                                                \
                if (n == 0 && !name##_group_visible(kobj))               \
                        return SYSFS_GROUP_INVISIBLE;                    \
                return name##_attr_visible(kobj, attr, n);               \
        }

#define DEFINE_SIMPLE_SYSFS_BIN_GROUP_VISIBLE(name)                   \
        static inline umode_t sysfs_group_visible_##name(             \
                struct kobject *kobj, struct bin_attribute *a, int n) \
        {                                                             \
                if (n == 0 && !name##_group_visible(kobj))            \
                        return SYSFS_GROUP_INVISIBLE;                 \
                return a->mode;                                       \
        }

#define SYSFS_GROUP_VISIBLE(fn) sysfs_group_visible_##fn
#endif

#endif /* __BACKPORT_LINUX_SYSFS_H */
