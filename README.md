# Introduction

This branch provides essential kernel patches required to run Intel® Xe Graphics Driver and its child drivers on Linux kernel v5.15. These patches are necessary alongside the [DKMS release](https://github.com/intel-gpu/xekmd-backports/tree/releases/main) modules to enable full driver functionality. The patches backport critical kernel subsystem features from upstream stable kernels. Without these patches, Xe driver features will have limitations or will not work at all.


# Patches and Features
Below are list of patches to enable the features , based on feature requirement apply them to your existing kernel build to enable Xe features.

| Feature | Subsystem | Commit | Kernel Version | Patch File |
|---------|-----------|--------|----------------|------------|
| PCIe – RAS AER Error handling | PCI | [PCI/AER: Allow drivers to opt in to Bus Reset on Non-Fatal errors](https://patch.msgid.link/28fd805043bb57af390168d05abb30898cf4fc58.1755008151.git.lukas@wunner.de) | v6.18 | [0001-PCI-AER-Allow-drivers-to-opt-in-to-Bus-Reset-on-Non-.patch]( https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-PCI-AER-Allow-drivers-to-opt-in-to-Bus-Reset-on-Non-.patch) |
| PCIe – RAS AER Error handling | PCI | [PCI/ERR: Ensure error recoverability at all times](https://patch.msgid.link/9e34ce61c5404e99ffdd29205122c6fb334b38aa.1763483367.git.lukas@wunner.de) | v6.19 | [0001-PCI-ERR-Ensure-error-recoverability-at-all-times.patch]( https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-PCI-ERR-Ensure-error-recoverability-at-all-times.patch) |
| PCIe – RAS AER Error handling | PCI | [PCI: Update saved_config_space upon resource assignment](https://lore.kernel.org/all/febc3f354e0c1f5a9f5b3ee9ffddaa44caccf651.1775.158054.git.lukas@wunner.de/) | v7.1 | [0001-PCI-Update-saved_config_space-upon-resource-assignme.patch]( https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-PCI-Update-saved_config_space-upon-resource-assignme.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: use new iterator in dma_resv_copy_fences](https://patchwork.freedesktop.org/patch/msgid/20211005113742.1101-5-christian.koenig@amd.com) | v5.16 | [`0001-dma-buf-use-new-iterator-in-dma_resv_copy_fences.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-use-new-iterator-in-dma_resv_copy_fences.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: use new iterator in dma_resv_get_fences v3](https://patchwork.freedesktop.org/patch/msgid/20211005113742.1101-6-christian.koenig@amd.com) | v5.16 | [`0001-dma-buf-use-new-iterator-in-dma_resv_get_fences-v.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-use-new-iterator-in-dma_resv_get_fences-v.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: use new iterator in dma_resv_wait_timeout](https://patchwork.freedesktop.org/patch/msgid/20211005113742.1101-7-christian.koenig@amd.com) | v5.16 | [`0001-dma-buf-use-new-iterator-in-dma_resv_wait_timeout.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-use-new-iterator-in-dma_resv_wait_timeout.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: use new iterator in dma_resv_test_signaled](https://patchwork.freedesktop.org/patch/msgid/20211005113742.1101-8-christian.koenig@amd.com) | v5.16 | [`0001-dma-buf-use-new-iterator-in-dma_resv_test_signale.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-use-new-iterator-in-dma_resv_test_signale.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: add dma_resv_for_each_fence v3](https://patchwork.freedesktop.org/patch/msgid/20211006123609.2026-1-christian.koenig@amd.com) | v5.16 | [`0001-dma-buf-add-dma_resv_for_each_fence-v3.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-add-dma_resv_for_each_fence-v3.patch) |
| DMA-RESV-USAGE | dma-resv | [dma-resv: Fix dma_resv_get_fences and dma_resv_copy_fences after conversion](https://patchwork.freedesktop.org/patch/msgid/20211008095007.972693-1-tvrtko.ursulin@linux.intel.com) | v5.16 | [`0001-dma-resv-Fix-dma_resv_get_fences-and-dma_resv_cop.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-resv-Fix-dma_resv_get_fences-and-dma_resv_cop.patch) |
| DMA-RESV-USAGE | dma-resv | Local | Custom (5.15) | [`0001-dma-resv-add-5.15-bridge-scaffold-for-usage-API.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-resv-add-5.15-bridge-scaffold-for-usage-API.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: add dma_resv_replace_fences v2](https://patchwork.freedesktop.org/patch/msgid/20220321135856.1331-1-christian.koenig@amd.com) | v5.19 | [`0001-dma-buf-add-dma_resv_replace_fences-v2.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-add-dma_resv_replace_fences-v2.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: add dma_resv_get_singleton v2](https://patchwork.freedesktop.org/patch/msgid/20220321135856.1331-3-christian.koenig@amd.com) | v5.19 | [`0001-dma-buf-add-dma_resv_get_singleton-v2.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-add-dma_resv_get_singleton-v2.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: add enum dma_resv_usage v4](https://patchwork.freedesktop.org/patch/msgid/20220407085946.744568-2-christian.koenig@amd.com) | v5.19 | [`0001-dma-buf-add-enum-dma_resv_usage-v4.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-add-enum-dma_resv_usage-v4.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: specify usage while adding fences to dma_resv obj v7](https://patchwork.freedesktop.org/patch/msgid/20220407085946.744568-3-christian.koenig@amd.com) | v5.19 | [`0001-dma-buf-specify-usage-while-adding-fences-to-dma_.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-specify-usage-while-adding-fences-to-dma_.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf & drm/amdgpu: remove dma_resv workaround](https://patchwork.freedesktop.org/patch/msgid/20220407085946.744568-4-christian.koenig@amd.com) | v5.19 | [`0001-dma-buf-drm-amdgpu-remove-dma_resv-workaround.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-drm-amdgpu-remove-dma_resv-workaround.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: add DMA_RESV_USAGE_KERNEL v3](https://patchwork.freedesktop.org/patch/msgid/20220407085946.744568-5-christian.koenig@amd.com) | v5.19 | [`0001-dma-buf-add-DMA_RESV_USAGE_KERNEL-v3.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-add-DMA_RESV_USAGE_KERNEL-v3.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: add DMA_RESV_USAGE_BOOKKEEP v3](https://patchwork.freedesktop.org/patch/msgid/20220407085946.744568-10-christian.koenig@amd.com) | v5.19 | [`0001-dma-buf-add-DMA_RESV_USAGE_BOOKKEEP-v3.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-add-DMA_RESV_USAGE_BOOKKEEP-v3.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: Remove the signaled bit status check](https://patchwork.freedesktop.org/patch/msgid/20220914164321.2156-2-Arvind.Yadav@amd.com) | v6.1 | [`0001-dma-buf-Remove-the-signaled-bit-status-check.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-Remove-the-signaled-bit-status-check.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: set signaling bit for the stub fence](https://patchwork.freedesktop.org/patch/msgid/20220914164321.2156-3-Arvind.Yadav@amd.com) | v6.1 | [`0001-dma-buf-set-signaling-bit-for-the-stub-fence.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-set-signaling-bit-for-the-stub-fence.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: dma_fence_wait must enable signaling](https://patchwork.freedesktop.org/patch/msgid/20220914164321.2156-5-Arvind.Yadav@amd.com) | v6.1 | [`0001-dma-buf-dma_fence_wait-must-enable-signaling.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-dma_fence_wait-must-enable-signaling.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: fix dma_fence_default_wait() signaling check](https://patchwork.freedesktop.org/patch/msgid/20220919120618.113332-1-christian.koenig@amd.com) | v6.1 | [`0001-dma-buf-fix-dma_fence_default_wait-signaling-chec.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-fix-dma_fence_default_wait-signaling-chec.patch) |
| DMA-RESV-USAGE | dma-buf | [dma-buf: actually set signaling bit for private stub fences](https://patchwork.freedesktop.org/patch/msgid/20230126002844.339593-1-dakr@redhat.com) | v6.3 | [`0001-dma-buf-actually-set-signaling-bit-for-private-st.patch`](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/backport/patches/base/0001-dma-buf-actually-set-signaling-bit-for-private-st.patch) |


# Patch Integration

Apply patches to your Linux kernel v5.15 LTS tree based on the features you require from the table above. All patches are available in the `backport/patches/base/` directory and listed in the `series` file.

To apply specific patches:

```bash
cd <your-kernel-tree>
git am /path/to/xekmd-backports/backport/patches/base/<patch-name>.patch
```

To apply all patches:

Follow the order from [series](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v5.15/series) file:

```bash
cd <your-kernel-tree>
git am /path/to/xekmd-backports/backport/patches/base/<patch-name>.patch
```

**Note:** This branch is regularly updated to track the latest Linux kernel v5.15 LTS releases, ensuring compatibility and stability.

# Testing and Validation

For testing purposes, use the `backport.sh` script to automatically download Linux kernel v5.15 and apply all patches from the series file. The script creates a patched kernel tree in the `kernel/` directory with each patch applied as a git commit.

```bash
./backport.sh -c
```

Build and install the patched kernel on your target system, then install the [DKMS release](https://github.com/intel-gpu/xekmd-backports/tree/releases/main) modules to verify full Xe driver functionality.

# Contributing

This branch does not accept direct patch contributions. All kernel patches must first be available in the kernel-backport branch (e.g., `kernel-backport/main`) either as part of the base kernel or as patches in that branch. Once patches are available there and the out-of-tree (OOT) backport utilizes those patches, they can be integrated into this branch.

For DKMS module contributions, please refer to the [oot-backport](https://github.com/intel-gpu/xekmd-backports/tree/oot-backport/main) branch.

# License

This work is a subset of the Linux kernel as such we keep the kernel's
Copyright practice. Some files may have their own copyright and in those
cases the license is mentioned in the file.
