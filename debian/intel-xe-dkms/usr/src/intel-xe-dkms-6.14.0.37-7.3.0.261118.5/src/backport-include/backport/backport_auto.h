/* src/backport-include/backport/backport_auto.h.  Generated from backport_auto.h.in by configure.  */
/* src/backport-include/backport/backport_auto.h.in.  Generated from configure.ac by autoheader.  */

/* access_remote_vm() function is not present or not exported */
/* #undef BPM_ACCESS_REMOTE_VM_NOT_PRESENT */

/* acpi_dev_for_each_child() is not available */
#define BPM_ACPI_DEV_FOR_EACH_CHILD_NOT_PRESENT 1

/* alloc_ordered_workqueue_lockdep_map not available */
#define BPM_ALLOC_ORDERED_WORKQUEUE_LOCKDEP_MAP_NOT_PRESENT 1

/* anon_inode_getfile_fmode() is not available */
#define BPM_ANON_INODE_GETFILE_FMODE_NOT_PRESENT 1

/* auxiliary_get_drvdata and auxiliary_set_drvdata is not available */
#define BPM_AUXILIARY_BUS_HELPERS_NOT_PRESENT 1

/* bitmap_weighted_or() is not present in kernel headers */
#define BPM_BITMAP_WEIGHTED_OR_NOT_PRESENT 1

/* class_create() still requires owner parameter */
#define BPM_CLASS_CREATE_NO_OWNER_NOT_PRESENT 1

/* struct class::devnode does not take const struct device * */
#define BPM_CLASS_DEVNODE_CONST_NOT_PRESENT 1

/* ACQUIRE/ACQUIRE_ERR/4-arg DEFINE_GUARD_COND not available */
#define BPM_CLEANUP_ACQUIRE_NOT_PRESENT 1

/* configfs_group_operations.is_visible not available */
#define BPM_CONFIGFS_GROUP_OPS_IS_VISIBLE_NOT_PRESENT 1

/* bin_attribute callbacks do not expect const parameter */
#define BPM_CONST_STRUCT_BIN_ATTRIBUTE_IS_NOT_PRESENT 1

/* dev_coredumpm_timeout() is not available */
#define BPM_COREDUMPM_TIMEOUT_NOT_PRESENT 1

/* __counted_by is not available in the kernel */
#define BPM_COUNTED_BY_NOT_PRESENT 1

/* COUNT_ARGS() does not support 15 arguments */
#define BPM_COUNT_ARGS_15_NOT_PRESENT 1

/* DEFINE_SYSFS_GROUP_VISIBLE is not avilable */
#define BPM_DEFINE_SYSFS_GROUP_VISIBLE_NOT_PRESENT 1

/* dev_coredump_put() is not available */
#define BPM_DEVCOREDUMP_PUT_NOT_PRESENT 1

/* device_iommu_capable() is not available */
#define BPM_DEVICE_IOMMU_CAPABLE_NOT_PRESENT 1

/* device_set_driver_override() is not available */
#define BPM_DEVICE_SET_DRIVER_OVERRIDE_NOT_PRESENT 1

/* struct dev_pagemap_ops has no folio_free member */
#define BPM_DEV_PAGEMAP_OPS_FOLIO_FREE_NOT_PRESENT 1

/* folio_split callback not present in dev_pagemap_ops */
#define BPM_DEV_PAGEMAP_OPS_FOLIO_SPLIT_NOT_PRESENT 1

/* dev_pm_smart_suspend is not available */
#define BPM_DEV_PM_SMART_SUSPEND_NOT_PRESENT 1

/* disable_delayed_work_sync is not declared in linux/workqueue.h */
#define BPM_DISABLE_DELAYED_WORK_SYNC_NOT_PRESENT 1

/* disable_work_sync() function is not avilable */
#define BPM_DISBALE_WORK_SYNC_NOT_PRESENT 1

/* DIV_U64_ROUND_UP macro is not avilable */
#define BPM_DIV_U64_ROUND_UP_NOT_PRESENT 1

/* dma_buf_attach_ops has no invalidate_mappings member */
#define BPM_DMA_BUF_ATTACH_OPS_INVALIDATE_MAPPINGS_NOT_PRESENT 1

/* dma_buf_invalidate_mappings() is not available */
#define BPM_DMA_BUF_INVALIDATE_MAPPINGS_NOT_PRESENT 1

/* dma_fence_array_alloc() is not available */
#define BPM_DMA_FENCE_ARRAY_ALLOC_NOT_PRESENT 1

/* Fence-array create/init without signal_on_any are unavailable */
#define BPM_DMA_FENCE_ARRAY_NO_SIGNAL_ON_ANY_NOT_PRESENT 1

/* dma_fence_check_and_signal_locked() is not available */
#define BPM_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT 1

/* dma_fence_enable_signaling() is not available */
#define BPM_DMA_FENCE_ENABLE_SIGNALING_NOT_PRESENT 1

/* dma_fence struct has no extern_lock member */
#define BPM_DMA_FENCE_EXTERN_LOCK_NOT_PRESENT 1

/* dma_fence_is_container() is not available in the kernel */
#define BPM_DMA_FENCE_IS_CONTAINER_NOT_PRESENT 1

/* dma_fence_lock_irqsave() and dma_fence_unlock_irqrestore() are not
   available */
#define BPM_DMA_FENCE_LOCK_IRQSAVE_AND_IRQRESTORE_NOT_PRESENT 1

/* dma_fence_set_deadline() is not available in the kernel */
#define BPM_DMA_FENCE_SET_DEADLINE_NOT_PRESENT 1

/* struct dma_iova_state is not available */
#define BPM_DMA_IOVA_STATE_NOT_PRESENT 1

/* dma_resv_add_fence() is not available in the kernel */
#define BPM_DMA_RESV_ADD_FENCE_NOT_PRESENT 1

/* dma_resv_for_each_fence() is not available in the kernel */
#define BPM_DMA_RESV_FOR_EACH_FENCE_NOT_PRESENT 1

/* dma_resv_replace_fences() is not available in the kernel */
#define BPM_DMA_RESV_REPLACE_FENCES_NOT_PRESENT 1

/* dma_resv_reserve_fences() is not available in the kernel */
#define BPM_DMA_RESV_RESERVE_FENCES_NOT_PRESENT 1

/* enum dma_resv_usage is not available in the kernel */
#define BPM_DMA_RESV_USAGE_NOT_PRESENT 1

/* Dmem cgroup common ancestor helper is not exported */
#define BPM_DMEM_CGROUP_ANCESTOR_NOT_EXPORTED 1

/* Dmem cgroup protection queries are not exported */
#define BPM_DMEM_CGROUP_PROTECTION_NOT_EXPORTED 1

/* struct pci_driver does not have driver_managed_dma member */
#define BPM_DRIVER_MANAGED_DMA_NOT_PRESENT 1

/* drmm_alloc_ordered_workqueue is not available */
#define BPM_DRMM_ALLOC_ORDERED_WORKQUEUE_NOT_PRESENT 1

/* drmm_cgroup_register_region is declared in drm/drm_drv.h */
#define BPM_DRMM_CGROUP_REGISTER_REGION_NOT_PRESENT 1

/* drmm_cgroup_register_region takes a region size */
/* #undef BPM_DRMM_CGROUP_REGISTER_REGION_SIZE_ARG */

/* drmm_mutex_init is not available */
#define BPM_DRMM_MUTEX_INIT_NOT_PRESENT 1

/* __drmm_workqueue_release is not available */
#define BPM_DRMM_WORKQUEUE_RELEASE_NOT_PRESENT 1

/* drm_buddy_block_trim() does not have 2nd Arugment not available */
/* #undef BPM_DRM_BUDDY_BLOCK_TRIM_2ND_ARG_NOT_PRESENT */

/* Neither GPU_BUDDY_CONTIGUOUS_ALLOCATION nor DRM_BUDDY_CONTIGUOUS_ALLOCATION
   is present */
#define BPM_DRM_BUDDY_CONTIGUOUS_ALLOCATION_NOT_PRESENT 1

/* drm_buddy_free_list() does not have 3rd Arugment not available */
/* #undef BPM_DRM_BUDDY_FREE_LIST_ARG3_NOT_PRESENT */

/* drm_coredump_printer_is_full function is not avilable */
#define BPM_DRM_COREDUMP_PRINTER_IS_FULL_NOT_PRESENT 1

/* drm_dbg_printer() not available */
/* #undef BPM_DRM_DBG_PRINTER_NOT_PRESENT */

/* drm_dbg_ratelimited() not available */
#define BPM_DRM_DBG_RATELIMITED_NOT_PRESENT 1

/* struct drm_device does not have huge_mnt member */
#define BPM_DRM_DEVICE_HUGE_MNT_NOT_PRESENT 1

/* DRM_DEV_WEDGED_EVENT does not have 3rd argument */
#define BPM_DRM_DEV_WEDGED_EVENT_ARG3_NOT_PRESENT 1

/* DRM_DEV_WEDGED_EVENT is not avilable */
#define BPM_DRM_DEV_WEDGED_EVENT_NOT_PRESENT 1

/* struct drm_driver .fbdev_probe member is not present */
#define BPM_DRM_DRIVER_FBDEV_PROBE_NOT_PRESENT 1

/* Target DRM core provides DRIVER_GEM_GPUVA */
/* #undef BPM_DRM_DRIVER_GEM_GPUVA_PRESENT */

/* struct drm_driver has gem_prime_mmap callback */
/* #undef BPM_DRM_DRIVER_GEM_PRIME_MMAP_PRESENT */

/* drm_driver PRIME callback fields are not available */
#define BPM_DRM_DRIVER_PRIME_CALLBACKS_NOT_PRESENT 1

/* drm_exec_init() takes only 2 arguments */
#define BPM_DRM_EXEC_INIT_ARG3_NOT_PRESENT 1

/* __dma_fence_is_later uses old signature with seqno and ops arguments */
#define BPM_DRM_FENCE_IS_LATER_ARG_DMA_FENCE_OPS_NOT_PRESENT 1

/* client_id field is not present in struct drm_file */
#define BPM_DRM_FILE_CLIENT_ID_NOT_PRESENT 1

/* drm_gem_object.gpuva.lock_dep_map not present when CONFIG_LOCKDEP is
   enabled */
#define BPM_DRM_GEM_GPUVA_LOCK_DEP_MAP_NOT_PRESENT 1

/* drm_gem_object.gpuva.lock (struct mutex) not present; kernel uses
   lock_dep_map pointer or no lock field */
#define BPM_DRM_GEM_GPUVA_MUTEX_NOT_PRESENT 1

/* struct drm_gem_object_funcs lacks evict callback */
#define BPM_DRM_GEM_OBJECT_FUNCS_EVICT_NOT_PRESENT 1

/* struct drm_gem_object_funcs lacks rss callback */
#define BPM_DRM_GEM_OBJECT_FUNCS_RSS_NOT_PRESENT 1

/* struct drm_gem_object_funcs lacks status callback */
#define BPM_DRM_GEM_OBJECT_FUNCS_STATUS_NOT_PRESENT 1

/* kernel drm_gem_object lacks gpuva field (pre-v6.1 kernels) */
#define BPM_DRM_GEM_OBJECT_GPUVA_MEMBER_NOT_PRESENT 1

/* DRM_GPUVA_OP_DRIVER enum member is not avilable */
#define BPM_DRM_GPUVA_OP_DRIVER_NOT_PRESENT 1

/* drm_gpuvm_bo_obtain_locked() is not present */
#define BPM_DRM_GPUVM_BO_OBTAIN_LOCKED_NOT_PRESENT 1

/* drm_gpuvm_madvise_ops_create() is not present */
#define BPM_DRM_GPUVM_MADVISE_OPS_CREATE_NOT_PRESENT 1

/* rename DRM GPUVM symbols to avoid conflicts with backport kernel
   implementation */
#define BPM_DRM_GPUVM_RENAMING_SYMBOLS 1

/* drm_gpuvm_sm_map_ops_create() is not present */
#define BPM_DRM_GPUVM_SM_MAP_OPS_CREATE_MAP_REQ_NOT_PRESENT 1

/* drm_line_printer() not available */
#define BPM_DRM_LINE_PRINTER_NOT_PRESENT 1

/* drm_memory_stats is not available */
#define BPM_DRM_MEMORY_STATS_NOT_PRESENT 1

/* debugfs_symlink field not present in drm_minor, manual symlink creation
   needed */
#define BPM_DRM_MINOR_DEBUGFS_SYMLINK_NOT_PRESENT 1

/* drm_mode_size_dumb() is not available, kernel < 7.0 */
#define BPM_DRM_MODE_SIZE_DUMB_NOT_PRESENT 1

/* drm_mode_size_dumb() is available, kernel >= 7.0 */
/* #undef BPM_DRM_MODE_SIZE_DUMB_PRESENT */

/* drm_print_hex_dump() not available */
#define BPM_DRM_PRINT_HEX_DUMP_NOT_PRESENT 1

/* drm show_fdinfo support is not available */
#define BPM_DRM_SHOW_FDINFO_NOT_PRESENT 1

/* drm_suballoc_alloc() not available */
#define BPM_DRM_SUBALLOC_ALLOC_NOT_PRESENT 1

/* DRM_WEDGE_RECOVERY_COLD_RESET is not available */
#define BPM_DRM_WEDGE_RECOVERY_COLD_RESET_NOT_PRESENT 1

/* DRM_WEDGE_RECOVERY_VENDOR flag not present */
#define BPM_DRM_WEDGE_RECOVERY_VENDOR_NOT_PRESENT 1

/* struct drm_wedge_task_info is not avilable */
#define BPM_DRM_WEDGE_TASK_INFO_NOT_PRESENT 1

/* DRIVER_DATE field is not present or not needed in drm_driver structure */
#define BPM_DRV_DATE_NOT_PRESENT 1

/* struct iommu_domain_ops does not have enforce_cache_coherency member */
#define BPM_ENFORCE_CACHE_COHERENCY_NOT_PRESENT 1

/* eventfd_signal() requires an extra count argument */
#define BPM_EVENTFD_SIGNAL_ARG1_NOT_PRESENT 1

/* EXPORT_SYMBOL_FOR_MODULES macro is not avilable */
#define BPM_EXPORT_SYMBOL_FOR_MODULES_NOT_PRESENT 1

/* whether FIELD_PREP_CONST is defined */
/* #undef BPM_FIELD_PREP_CONST_NOT_PRESENT */

/* folio_put() is not available in the kernel */
#define BPM_FOLIO_PUT_NOT_PRESENT 1

/* folio_set_zone_device_data() is not available */
#define BPM_FOLIO_SET_ZONE_DEVICE_DATA_NOT_PRESENT 1

/* folio_zone_device_data() is not available */
#define BPM_FOLIO_ZONE_DEVICE_DATA_NOT_PRESENT 1

/* struct follow_pfnmap_args does not have addr_mask member */
#define BPM_FOLLOW_PFNMAP_ARGS_ADDR_MASK_NOT_PRESENT 1

/* follow_pfnmap_start/end() is not available */
#define BPM_FOLLOW_PFNMAP_START_NOT_PRESENT 1

/* whether FOP_UNSIGNED_OFFSET is defined */
/* #undef BPM_FOP_UNSIGNED_OFFSET_NOT_PRESENT */

/* for_each_if is not in linux/util_macros.h */
#define BPM_FOR_EACH_IF_NOT_PRESENT 1

/* for_each_or_bit is not available */
#define BPM_FOR_EACH_OR_BIT_NOT_PRESENT 1

/* __free() cleanup attribute is not supported */
#define BPM_FREE_ATTRIBUTE_NOT_PRESENT 1

/* generic_handle_irq_safe() is not available */
#define BPM_GENERIC_HANDLE_IRQ_SAFE_NOT_PRESENT 1

/* genlmsg_iput() API is not available */
#define BPM_GENLMSG_IPUT_NOT_PRESENT 1

/* genl_info_dump() API is not available */
#define BPM_GENL_INFO_DUMP_NOT_PRESENT 1

/* GENL_REQ_ATTR_CHECK() macro is not available */
#define BPM_GENL_REQ_ATTR_CHECK_NOT_PRESENT 1

/* genl_split_ops API is not available */
#define BPM_GENL_SPLIT_OPS_NOT_PRESENT 1

/* GENMASK_U32 macro is not avilable */
#define BPM_GENMASK_U32_NOT_PRESENT 1

/* hmm_pfn_to_phys() is not available */
#define BPM_HMM_PFN_TO_PHYS_NOT_PRESENT 1

/* hmm_range_fault_unlocked_timeout() is not available */
#define BPM_HMM_RANGE_FAULT_UNLOCKED_TIMEOUT_NOT_PRESENT 1

/* HRTIMER_SETUP macro is not avilable */
#define BPM_HRTIMER_SETUP_NOT_PRESENT 1

/* init_llist_node() is not available, kernel < 6.12 */
#define BPM_INIT_LLIST_NODE_NOT_PRESENT 1

/* init_llist_node() is available, kernel >= 6.12 */
/* #undef BPM_INIT_LLIST_NODE_PRESENT */

/* iommu_group_claim_dma_owner() is not available */
#define BPM_IOMMU_GROUP_CLAIM_DMA_OWNER_NOT_PRESENT 1

/* iommu_group_has_isolated_msi() is not available */
#define BPM_IOMMU_GROUP_HAS_ISOLATED_MSI_NOT_PRESENT 1

/* iommu_map() does not have gfp parameter */
#define BPM_IOMMU_MAP_GFP_NOT_PRESENT 1

/* iommu_paging_domain_alloc() is not available */
#define BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT 1

/* irq_bypass_register_producer() does not have eventfd argument */
/* #undef BPM_IRQ_BYPASS_REGISTER_PRODUCER_EVENTFD_NOT_PRESENT */

/* irq_bypass_register_producer() does not have irq argument */
/* #undef BPM_IRQ_BYPASS_REGISTER_PRODUCER_IRQ_NOT_PRESENT */

/* is_device_coherent_page() is not present */
#define BPM_IS_DEVICE_COHERENT_PAGE_NOT_PRESENT 1

/* kmalloc_objs() is not available */
#define BPM_KMALLOC_OBJS_NOT_PRESENT 1

/* kmalloc_obj() is not available */
#define BPM_KMALLOC_OBJ_NOT_PRESENT 1

/* kmap_local_page_try_from_panic exists but takes non-const struct page * */
/* #undef BPM_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NONCONST_PRESENT */

/* kmap_local_page_try_from_panic is not available */
#define BPM_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NOT_PRESENT 1

/* kvmalloc_objs() is not available */
#define BPM_KVMALLOC_OBJS_NOT_PRESENT 1

/* kvrealloc_noprof() is available */
/* #undef BPM_KVREALLOC_NOPROF_PRESENT */

/* kvrealloc() requires oldsize parameter */
#define BPM_KVREALLOC_OLDSIZE_PARAM_PRESENT 1

/* kvzalloc_objs() is not available */
#define BPM_KVZALLOC_OBJS_NOT_PRESENT 1

/* kzalloc_flex() is not available */
#define BPM_KZALLOC_FLEX_NOT_PRESENT 1

/* kzalloc_objs() is not available */
#define BPM_KZALLOC_OBJS_NOT_PRESENT 1

/* kzalloc_obj() is not available */
#define BPM_KZALLOC_OBJ_NOT_PRESENT 1

/* linear_page_delta() is not available */
#define BPM_LINEAR_PAGE_DELTA_NOT_PRESENT 1

/* linux/mei_uuid.h is not available */
#define BPM_LINUX_MEI_UUID_H_NOT_PRESENT 1

/* list_count_nodes() is not available */
#define BPM_LIST_COUNT_NODES_NOT_PRESENT 1

/* Define to 1 if list_lru_add does not have 4 arguments (nid, memcg) */
#define BPM_LIST_LRU_ADD_4ARGS_NOT_PRESENT 1

/* list_lru_add() exported symbol is not available */
/* #undef BPM_LIST_LRU_ADD_EXP_SYM_NOT_PRESENT */

/* Define if list_lru walk callback has no cb parameter */
#define BPM_LIST_LRU_WALK_CB_PARAM_NOT_PRESENT 1

/* local64_try_cmpxchg is not available */
#define BPM_LOCAL64_TRY_CMPXCHG_NOT_PRESENT 1

/* struct vfio_device_ops does not have match_token_uuid member */
#define BPM_MATCH_TOKEN_UUID_NOT_PRESENT 1

/* class_register() does not take const struct class * */
#define BPM_MEI_CLASS_BUS_REGISTER_CONST_ARGS_NOT_PRESENT 1

/* const argument not supported in struct bus_type match callback */
#define BPM_MEI_CL_DEVICE_MATCH_CONST_ARG_NOT_PRESENT 1

/* const argument not supported in struct bus_type uevent callback */
#define BPM_MEI_CL_DEVICE_UEVENT_CONST_ARG_NOT_PRESENT 1

/* migrate_device_pages()/finalize() not present */
#define BPM_MIGRATE_DEVICE_PAGES_NOT_PRESENT 1

/* migrate_device_pfns() not present */
#define BPM_MIGRATE_DEVICE_PFNS_NOT_PRESENT 1

/* struct migrate_vma fault_page member is not present */
#define BPM_MIGRATE_VMA_FAULT_PAGE_NOT_PRESENT 1

/* migrate_vma_* helpers are not present or not exported */
#define BPM_MIGRATE_VMA_NOT_PRESENT 1

/* Compound migration flags are unavailable */
#define BPM_MIGRATE_VMA_SELECT_COMPOUND_NOT_PRESENT 1

/* Define to 1 if mmu_interval_notifier_ops lacks two-pass invalidate
   callbacks */
#define BPM_MMU_INTERVAL_NOTIFIER_TWOPASS_NOT_PRESENT 1

/* module_import_ns quoted namespace strings are not supported */
/* #undef BPM_MODULE_IMPORT_TO_STRING_LITERAL_PRESENT */

/* struct pci_dev does not have non_mappable_bars member */
#define BPM_NON_MAPPABLE_BARS_NOT_PRESENT 1

/* NR_GPU_ACTIVE and NR_GPU_RECLAIM are available */
#define BPM_NR_GPU_STATS_NOT_PRESENT 1

/* num_pages_contiguous is not available */
#define BPM_NUM_PAGES_CONTIGUOUS_NOT_PRESENT 1

/* enable objtool-safe module init/exit aliases */
/* #undef BPM_OBJTOOL_COPY_ATTRIBUTE_NEEDED */

/* page_pgmap() helper is not available */
#define BPM_PAGE_PGMAP_NOT_PRESENT 1

/* parse_int_array_user() function is not present or not exported */
#define BPM_PARSE_INT_ARRAY_USER_NOT_PRESENT 1

/* pcie_aer_is_native() exported symbol is not available */
/* #undef BPM_PCIE_AER_IS_NATIVE_EXP_SYM_NOT_PRESENT */

/* pcim_iomap_region() is not available */
#define BPM_PCIM_IOMAP_REGION_NOT_PRESENT 1

/* pcim_p2pdma_provider() function not available */
#define BPM_PCIM_P2PDMA_NOT_PRESENT 1

/* pci_clear_and_set_config_dword() function not available */
#define BPM_PCI_CLEAR_AND_SET_CONFIG_DWORD_NOT_PRESENT 1

/* pci_iov_get_pf_drvdata() function not available */
#define BPM_PCI_IOV_GET_PF_DRVDATA_NOT_PRESENT 1

/* pci_iov_vf_bar_get_sizes and pci_iov_vf_bar_set_size functions not
   available */
#define BPM_PCI_IOV_VF_BAR_FUNCTIONS_NOT_PRESENT 1

/* pci_iov_vf_id() function not available */
#define BPM_PCI_IOV_VF_ID_NOT_PRESENT 1

/* pci_msix_can_alloc_dyn/pci_msix_alloc_irq_at/irq_domain_instantiate not
   available */
#define BPM_PCI_MSIX_ALLOC_IRQ_NOT_PRESENT 1

/* pci_rebar_size_supported and related helpers not available */
#define BPM_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT 1

/* pci_resize_resource does not take exclude_bars 4th argument */
#define BPM_PCI_RESIZE_RESOURCE_VF_BARS_NOT_PRESENT 1

/* Exported no-argument perf_allow_cpu() is unavailable */
#define BPM_PERF_ALLOW_CPU_NOT_PRESENT 1

/* perf_allow_kernel() is not exported to modules */
/* #undef BPM_PERF_ALLOW_KERNEL_NOT_EXPORTED */

/* perf_allow_kernel() requires an event attribute */
#define BPM_PERF_ALLOW_KERNEL_NO_ARGS_NOT_PRESENT 1

/* platform_device.remove callback returns int */
#define BPM_PF_DRIVER_REMOVE_RETURN_VOID_NOT_PRESENT 1

/* pin_user_pages_remote() does not have the 6-argument signature */
#define BPM_PIN_USER_PAGES_REMOTE_ARG6_NOT_PRESENT 1

/* PMD_ORDER macro is not available in linux/pgtable.h */
#define BPM_PMD_ORDER_NOT_PRESENT 1

/* struct pmu does not have scope member */
#define BPM_PMU_SCOPE_MEMBER_NOT_PRESENT 1

/* pm_runtime_*autosuspend() helpers do not mark last_busy */
/* #undef BPM_PM_RUNTIME_AUTOSUSPEND_MARK_LAST_BUSY_NOT_PRESENT */

/* pm_runtime_get_if_active() does not have 2nd Arugment not available */
/* #undef BPM_PM_RUNTIME_GET_IF_ACTIVE_ARG2_NOT_PRESENT */

/* PM_SUSPEND_IN_PROGRESS function is not avilable */
#define BPM_PM_SUSPEND_IN_PROGRESS_NOT_PRESENT 1

/* range_overflows() is not provided by the kernel */
#define BPM_RANGE_OVERFLOWS_NOT_PRESENT 1

/* register_shrinker second argument is not present */
#define BPM_REGISTER_SHRINKER_ARG2_NOT_PRESENT 1

/* secs_to_jiffies() function is not available */
#define BPM_SECS_TO_JIFFIES_NOT_PRESENT 1

/* shmem_read_folio() is not available in the kernel */
#define BPM_SHMEM_READ_FOLIO_NOT_PRESENT 1

/* shmem_writeout is not available */
#define BPM_SHMEM_WRITEOUT_NOT_PRESENT 1

/* shmem_write_folio() is not available */
#define BPM_SHMEM_WRITE_FOLIO_NOT_PRESENT 1

/* shrinker_alloc/register/free API not present */
#define BPM_SHRINKER_ALLOC_NOT_PRESENT 1

/* spi_driver.remove callback returns int */
#define BPM_SPI_DRIVER_REMOVE_RETURN_VOID_NOT_PRESENT 1

/* strscpy() argument3 is not available */
#define BPM_STRSCPY_ARG3_PRESENT 1

/* struct bin_attribute does not have read_new member */
#define BPM_STRUCT_BIN_ATTRIBUTE_READ_NEW_NOT_PRESENT 1

/* const keyword not supported for struct ctl_table */
#define BPM_STRUCT_CTL_TABLE_CONST_KEYWORD_NOT_PRESENT 1

/* struct device has no driver_override member */
#define BPM_STRUCT_DEVICE_DRIVER_OVERRIDE_NOT_PRESENT 1

/* origin member is not part of "struct drm_printer" */
#define BPM_STRUCT_DRM_PRINTER_ORIGIN_NOT_PRESENT 1

/* str_down_up() is not available */
#define BPM_STR_DOWN_UP_NOT_PRESENT 1

/* str_plural() is not available */
#define BPM_STR_PLURAL_NOT_PRESENT 1

/* str_up_down() is not available */
#define BPM_STR_UP_DOWN_NOT_PRESENT 1

/* legacy register_sysctl path requires explicit ctl_table sentinel */
/* #undef BPM_SYSCTL_TABLE_SENTINEL_NOT_PRESENT */

/* system_percpu_wq not available */
#define BPM_SYSTEM_PERCPU_WQ_NOT_PRESENT 1

/* timer_delete() function is not available */
#define BPM_TIMER_DELETE_NOT_PRESENT 1

/* bitmap_weighted_or() is not present in kernel headers */
#define BPM_UNDERSCORE_BITMAP_WEIGHTED_OR_NOT_PRESENT 1

/* us_to_ktime() function is not available */
#define BPM_US_TO_KTIME_NOT_PRESENT 1

/* uuid_le_cmp() is not available */
#define BPM_UUID_LE_CMP_NOT_PRESENT 1

/* struct vfio_device_ops does not have get_region_info_caps member */
#define BPM_VFIO_GET_REGION_INFO_CAPS_NOT_PRESENT 1

/* vma_alloc_folio still takes 5 args including hugepage */
#define BPM_VMA_ALLOC_FOLIO_4ARGS_NOT_PRESENT 1

/* vma_end_pgoff() is not available */
#define BPM_VMA_END_PGOFF_NOT_PRESENT 1

/* vma_flags_t type is not available */
#define BPM_VMA_FLAGS_T_NOT_PRESENT 1

/* vma_get_page_prot() is not available */
#define BPM_VMA_GET_PAGE_PROT_NOT_PRESENT 1

/* vma_is_cow_mapping() is not available */
#define BPM_VMA_IS_COW_MAPPING_NOT_PRESENT 1

/* vmf_insert_pfn_pmd()/vmf_insert_pfn_pud() expect pfn_t argument */
#define BPM_VMF_INSERT_PFN_ARG_PFN_T_NOT_PRESENT 1

/* vm_flags_set() is not available in the kernel */
#define BPM_VM_FLAGS_SET_NOT_PRESENT 1

/* i2c-designware lacks Intel Xe polling/quirk; disable xe_i2c */
#define BPM_XE_I2C_NOT_SUPPORTED 1

/* Unbound parent PCI bridge should disable PM and emit warning */
/* #undef BPM_XE_PM_UNBOUNDED_BRIDGE_DISABLE_PM */

/* zone_device_folio_init() is not available, use page concept */
#define BPM_ZONE_DEVICE_FOLIO_INIT_NOT_PRESENT 1

/* zone_device_page_init does not take 1 arg */
#define BPM_ZONE_DEVICE_PAGE_INIT_1ARG_NOT_PRESENT 1

/* zone_device_page_init does not take 2 args */
#define BPM_ZONE_DEVICE_PAGE_INIT_2ARGS_NOT_PRESENT 1

/* zone_device_page_init does not take 3 args */
#define BPM_ZONE_DEVICE_PAGE_INIT_3ARGS_NOT_PRESENT 1

/* Define to 1 if you have the <drm/display/drm_hdcp.h> header file. */
#define HAVE_DRM_DISPLAY_DRM_HDCP_H 1

/* Define to 1 if you have the <drm/drm_accel.h> header file. */
#define HAVE_DRM_DRM_ACCEL_H 1

/* Define to 1 if you have the <drm/drm_gpuva_mgr.h> header file. */
/* #undef HAVE_DRM_DRM_GPUVA_MGR_H */

/* Define to 1 if you have the <drm/drm_module.h> header file. */
#define HAVE_DRM_DRM_MODULE_H 1

/* Define to 1 if you have the <drm/drm_privacy_screen_machine.h> header file.
   */
#define HAVE_DRM_DRM_PRIVACY_SCREEN_MACHINE_H 1

/* Define to 1 if you have the <drm/i915_gsc_proxy_mei_interface.h> header
   file. */
/* #undef HAVE_DRM_I915_GSC_PROXY_MEI_INTERFACE_H */

/* Define to 1 if you have the <drm/intel/i915_drm.h> header file. */
#define HAVE_DRM_INTEL_I915_DRM_H 1

/* Define to 1 if you have the <drm/intel/i915_gsc_proxy_mei_interface.h>
   header file. */
#define HAVE_DRM_INTEL_I915_GSC_PROXY_MEI_INTERFACE_H 1

/* Define to 1 if you have the <kunit/static_stub.h> header file. */
#define HAVE_KUNIT_STATIC_STUB_H 1

/* Define to 1 if you have the <linux/args.h> header file. */
#define HAVE_LINUX_ARGS_H 1

/* Define to 1 if you have the <linux/cleanup.h> header file. */
#define HAVE_LINUX_CLEANUP_H 1

/* Define to 1 if you have the <linux/container_of.h> header file. */
#define HAVE_LINUX_CONTAINER_OF_H 1

/* Define to 1 if you have the <linux/dma-iommu.h> header file. */
/* #undef HAVE_LINUX_DMA_IOMMU_H */

/* Define to 1 if you have the <linux/gpu_buddy.h> header file. */
/* #undef HAVE_LINUX_GPU_BUDDY_H */

/* Define to 1 if you have the <linux/iosys-map.h> header file. */
#define HAVE_LINUX_IOSYS_MAP_H 1

/* Define to 1 if you have the <linux/mei_aux.h> header file. */
#define HAVE_LINUX_MEI_AUX_H 1

/* Define to 1 if you have the <linux/mutex_types.h> header file. */
#define HAVE_LINUX_MUTEX_TYPES_H 1

/* Define to 1 if you have the <linux/sprintf.h> header file. */
#define HAVE_LINUX_SPRINTF_H 1

/* Define to 1 if you have the <linux/string_choices.h> header file. */
#define HAVE_LINUX_STRING_CHOICES_H 1

/* Define to 1 if you have the <linux/unaligned.h> header file. */
#define HAVE_LINUX_UNALIGNED_H 1

/* Define to 1 if you have the <linux/wordpart.h> header file. */
#define HAVE_LINUX_WORDPART_H 1

/* Define to 1 if you have the <linux/workqueue_types.h> header file. */
#define HAVE_LINUX_WORKQUEUE_TYPES_H 1

/* Name of package */
#define PACKAGE "intel-xe-drm"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "linux-graphics@intel.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "intel-xe-drm"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "intel-xe-drm 1.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "intel-xe-drm"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.0"

/* Version number of package */
#define VERSION "1.0"
