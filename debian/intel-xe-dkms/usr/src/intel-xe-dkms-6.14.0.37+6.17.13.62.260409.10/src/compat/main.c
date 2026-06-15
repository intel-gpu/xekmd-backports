#include <linux/module.h>
#include <linux/init.h>
#include <linux/pm_qos.h>
#include <linux/workqueue.h>

MODULE_AUTHOR("Luis R. Rodriguez");
MODULE_DESCRIPTION("Kernel backport module");
MODULE_LICENSE("GPL");

#ifndef CPTCFG_KERNEL_NAME
#error "You need a CPTCFG_KERNEL_NAME"
#endif

#ifndef CPTCFG_BASE_KERNEL_HEAD
#error "You need a CPTCFG_BASE_KERNEL_HEAD"
#endif

#ifndef CPTCFG_BACKPORTS_RELEASE_TAG
#error "You need a CPTCFG_BACKPORTS_RELEASE_TAG"
#endif

#ifndef CPTCFG_TARGET_KERNEL_NAME
#error "You need a CPTCFG_TARGET_KERNEL_NAME"
#endif

static char *backported_kernel_name = CPTCFG_KERNEL_NAME;

module_param(backported_kernel_name, charp, 0400);
MODULE_PARM_DESC(backported_kernel_name,
		 "The kernel tree name that was used for this backport (" CPTCFG_KERNEL_NAME ")");

#ifdef BACKPORTS_GIT_TRACKED
static char *backports_tracker_id = BACKPORTS_GIT_TRACKED;
module_param(backports_tracker_id, charp, 0400);
MODULE_PARM_DESC(backports_tracker_id,
		 "The version of the tree containing this backport (" BACKPORTS_GIT_TRACKED ")");
#else
static char *backported_kernel_version = CPTCFG_BASE_KERNEL_HEAD;
static char *backports_version = CPTCFG_BACKPORTS_RELEASE_TAG;

module_param(backported_kernel_version, charp, 0400);
MODULE_PARM_DESC(backported_kernel_version,
		 "The kernel version that was used for this backport (" CPTCFG_BASE_KERNEL_HEAD ")");

module_param(backports_version, charp, 0400);
MODULE_PARM_DESC(backports_version,
		"Backported from tag (" CPTCFG_BACKPORTS_RELEASE_TAG ") of tree https://github.com/intel-gpu/xekmd-backports");

#endif

void backport_dependency_symbol(void)
{
}
EXPORT_SYMBOL_GPL(backport_dependency_symbol);


static int __init backport_init(void)
{
	printk(KERN_INFO "COMPAT: Backport init, Module is backported from " CPTCFG_BASE_KERNEL_TAG " against Kernel " CPTCFG_TARGET_KERNEL_NAME " \n");

        return 0;
}
subsys_initcall(backport_init);

static void __exit backport_exit(void)
{
}
module_exit(backport_exit);
