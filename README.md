
# Introduction

This repo is intended to provide a preview of Intel® Graphics Driver (xe) for the next generation of GPUs, which are yet to be fully available on the mainline kernel.

This repo contains patches that are already merged in [drm-tip](https://gitlab.freedesktop.org/drm/tip) or sent to drm mailing list for review.

Since it is just for showcasing the capabilities of the next-gen GPUs so quality is not guaranteed and any issue needs to be reproduced and reported on [drm-tip](https://drm.pages.freedesktop.org/intel-docs/how-to-file-i915-bugs.html).


# Contains
|   |   | |
|-- |---|-- |
|1. | Patches from drm-tip.| backport/patches/base | |
|2. | Feature patches send to public mailing list for review |backport/patches/features |
|3. | Script to create kernel | backport.sh|
|4. | File containing list of patches to pick-up and apply on top of kernel | series|

Note: 
1. Patches present in base will be removed once merged in mainline kernel.
2. Patches present in features are dynamic in nature, they may change frequently and removed once merged in drm-tip.
3. Patches present in features will use prelim uapi to aviod conflict in updates, once patches are merged in drm-tip, uapi will change from prelim to normal.
4. prelim uapi will be maintained at [drm-uapi-helper](https://github.com/intel-gpu/drm-uapi-helper/tree/xe).

# Available Branches

| Branch Name | Kernel Version | Status |
|-------------|----------------|--------|
| kernel-backport/main_6.14 | 6.14 | Running |
| kernel-backport/main_6.11 | 6.11 | Frozen |

**Note:** Choose the appropriate branch based on your target kernel version. Frozen branches are no longer actively maintained.

# Usage
We download a stable Linux kernel and maintain all custom changes as patch files listed in series files.
These patches are organized in the base and features directories. When creating a kernel tree, the patches from the series files are applied on top of the downloaded kernel, resulting in a custom kernel tree with all required changes.
backport.sh < options >

||options |description |
|-- |--|--| 
|1. |create-tree| Create kernel tree based on given option <base/features> (default)|
|2. |delete-tree| Delete the tree|
|3. |reset-tree| Delete the existing tree and re-create it|
|4. |override| Overrides existing tree|

# Debugging

## Building and Testing Custom Kernel

After creating the custom kernel tree using `./backport.sh`, you can build and test your changes:

### 1. Navigate to Kernel Tree and Make Changes
```bash
cd <generated-kernel-tree>
```

The kernel tree is maintained by git, allowing you to track and manage changes.

**Make your code changes** in the kernel tree (edit driver files, add features, fix bugs, etc.) before proceeding to build.
### 2. First Build - Create DEB Package
For the initial build, compile and install the complete DEB package:

### 3. Subsequent Builds - Build .ko Module Only
From the next iteration onwards, you can build only the kernel module (.ko) for faster testing

### 4. Add and Commit Changes
Track your changes using git:

```bash
git add <modified-files>
git commit -m "Your change description"
```
# Contributing

## Adding Patches

### 1. Create Your Patch
Generate patch files from your generated kernel folder:
```bash
git format-patch -N1 <commit-hash> --zero-commit
```

### 2. Choose Location
Place the patch in the appropriate directory based on patch type:

#### Directory Structure:
```
backport/patches/
├── base/           # All fixes and patches merged in drm-tip
└── features/       # Feature patches under review
    ├── eu-debug/
    ├── sriov/
    └── xe-late-bind-fw/
```

#### Placement Rules:
- **`backport/patches/base/`** - For all fixes and patches already merged in drm-tip
- **`backport/patches/features/<feature-name>/`** - For new feature patches under review
  - Place feature patches in the appropriate feature subdirectory
  - If the feature directory doesn't exist, create one with a descriptive name

**Examples:**
- Bug fix → `backport/patches/base/0001-fix-memory-leak.patch`
- SR-IOV feature → `backport/patches/features/sriov/0001-add-sriov-support.patch`
- EU Debug feature → `backport/patches/features/eu-debug/0001-enable-eu-debug.patch`

### 3. Copy Patch File
```bash
# For base patches
cp <your-patch>.patch backport/patches/base/

# For feature patches
cp <your-patch>.patch backport/patches/features/<feature-name>
```

### 4. Update Series File
Add your created patch to the "series" file in the repo folder.

* For base patches - add to the end of base section "# base"
* For feature patches - add to the feature section denoted by "# < feature-name > "; For example: "# sriov"

**Important Notes:**
- **Patch numbering**: All patches must start with `0001-` prefix (not sequential numbering)
- **Patch order matters**: Place patches according to their dependencies in the series file
- **Manual editing**: You can also manually edit the series file to insert patches at specific positions

**Example series file:**
```
0001-fix-initialization.patch
0001-add-new-feature.patch
0001-update-documentation.patch
```

### 5. Verify
Test that patches apply correctly. This will generate the kernel tree with your changes:
```bash
./backport.sh create-tree [base|features]
```

**Important:** Ensure there are **no conflicts** during tree generation. If conflicts occur, the patch cannot be merged and must be resolved before submission.

After successful tree generation, verify your changes:

### 6. Submit
- Commit your changes (patch file + series file update)
- Create a pull request with clear description
- Reference upstream commit or mailing list discussion

# License

This work is a subset of the Linux kernel as such we keep the kernel's
Copyright practice. Some files may have their own copyright and in those
cases the license is mentioned in the file.
