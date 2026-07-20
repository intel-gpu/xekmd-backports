# Introduction

This branch provides essential kernel patches required to run Intel® Xe Graphics Driver and its child drivers on Linux kernel v6.6. These patches are necessary alongside the [DKMS release](https://github.com/intel-gpu/xekmd-backports/tree/releases/main) modules to enable full driver functionality. The patches backport critical kernel subsystem features from upstream stable kernels. Without these patches, Xe driver features will have limitations or will not work at all.


# Patches and Features
Below are list of patches to enable the features , based on feature requirement apply them to your existing kernel build to enable Xe features.

| Feature | Subsystem | Commit | Kernel Version | Patch File |
|---------|-----------|--------|----------------|------------|
|         |           |        |                |            |

# Patch Integration

Apply patches to your Linux kernel v6.6 LTS tree based on the features you require from the table above. All patches are available in the `backport/patches/base/` directory and listed in the `series` file.

To apply specific patches:

```bash
cd <your-kernel-tree>
git am /path/to/xekmd-backports/backport/patches/base/<patch-name>.patch
```

To apply all patches:

Follow the order from [series](https://github.com/intel-gpu/xekmd-backports/blob/target-kernel/v6.6/series) file:

```bash
cd <your-kernel-tree>
git am /path/to/xekmd-backports/backport/patches/base/<patch-name>.patch
```

**Note:** This branch is regularly updated to track the latest Linux kernel v6.6 LTS releases, ensuring compatibility and stability.

# Testing and Validation

For testing purposes, use the `backport.sh` script to automatically download Linux kernel v6.6 and apply all patches from the series file. The script creates a patched kernel tree in the `kernel/` directory with each patch applied as a git commit.

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
