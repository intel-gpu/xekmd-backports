# Developer Guide: DKMS Packages and Debug Patches

This guide explains how to build a DKMS package from the current source tree and how to include a temporary patch for debugging.

## Table of contents

1. [Source path mapping](#1-source-path-mapping)
2. [Applying debug patches](#2-applying-debug-patches)
   - [2.1 Applying patches](#21-applying-patches)
   - [2.2 Handling conflicts](#22-handling-conflicts)
   - [2.3 Updating version](#23-updating-version)
   - [2.4 Reviewing and removing debug changes](#24-reviewing-and-removing-debug-changes)
3. [Building a DKMS package](#3-building-a-dkms-package)
   - [Compile validation before packaging](#compile-validation-before-packaging)
   - [Debian / Ubuntu](#debian--ubuntu)
   - [RPM-based distributions](#rpm-based-distributions)
4. [Creating Kernel-Tree Patches](#4-creating-kernel-tree-patches)

## 1. Source path mapping

The `src/` directory mirrors kernel-tree paths. For example, `drivers/gpu/drm/xe/xe_gt.c` in a kernel tree is `src/drivers/gpu/drm/xe/xe_gt.c` in this repository.

## 2. Applying debug patches

The DKMS package is built from the current driver source tree. To include a debug fix, apply the patch to the source files before building the package. Simply copying a `.patch` file into the repository does not apply it.

Start from the repository revision you want to test and review the current changes:

```sh
git status --short
```

Preserve any existing work in the tree; do not discard changes you still need. Run the commands below from the repository root.

Patches downloaded from a mailing list or exported from drm-tip or a development kernel tree normally use kernel-tree paths such as `drivers/gpu/drm/xe/xe_gt.c`. In this DKMS repository, the corresponding file is `src/drivers/gpu/drm/xe/xe_gt.c`.

For ML mail patches, use `git am` as the default. It preserves one commit per patch, making it straightforward to fold fixes into the appropriate patch. For a series you intend to resubmit, maintain and export it from a kernel-tree worktree so patch paths do not contain `src/`.

### 2.1 Applying patches

Apply the original ML mail patches in order. Their paths should be kernel-tree paths, without a `src/` prefix:

```sh
git am --directory=src /path/to/series/*.patch
```

### 2.2 Handling conflicts

When `git am` stops on a conflict, it pauses at the current mail patch. Inspect the diagnostics and `git status`, resolve the affected files, stage the resolutions, then continue:

```sh
git add src/path/to/resolved-file.c
git am --continue
```

Use `git am --skip` only if you intend to omit the current patch. Use `git am --abort` to cancel the in-progress series. Later patches are not applied until the current patch is resolved or skipped.

### 2.3 Updating version

The runtime driver version comes from `BACKPORTS_RELEASE_TAG` in [src/versions](src/versions). For a local debug build, preserve the base release fields and add your unique debug identifier before `_v`. Coordinate identifiers when sharing a base so each debug build has a distinct tag. The full tag is included in the driver's version message, which makes it useful for identifying the running debug build. Change only `BACKPORTS_RELEASE_TAG`; preserve `BASE_KERNEL_TAG`, `BASE_KERNEL_HEAD`, and the actual release fields. Keep this local debug identifier out of the ML patch series.

`BUILD_VERSION` is separate: it sets the package release/revision, not the driver's reported version. Assign a unique value when building packages in parallel or when you need distinct package artifacts:

```sh
make xe-dkms-deb-pkg BUILD_VERSION=101
make xe-dkms-rpm-pkg BUILD_VERSION=101
```

Use a different coordinated value for each engineer's package. Do not rely on the default package revision when multiple builds share the same kernel and backport release.

Preserve the underscore-separated fields in `BACKPORTS_RELEASE_TAG`; the package version is derived from those fields by the build system.

### 2.4 Reviewing and removing debug changes

Before building, review the changes and confirm only the intended debug changes remain.

After testing, remove only debug changes that are no longer needed. On a dedicated test branch, revert the test commits in reverse order. Preserve unrelated work and restore the original release tag only after removing the debug changes.

## 3. Building a DKMS package

DKMS packages contain the driver source and build the kernel modules for the target kernel when the package is installed. Packaging alone does not establish that a debug patch compiles. **Compile the patched source locally before creating and distributing the package**, rather than discovering compilation errors during installation.

Kernel headers are needed for the separate compile-validation step and for the DKMS build on the installation system, not for creating the source-only DKMS package itself. Do not pass a headers path to the packaging commands below.

Run the commands from the repository root after applying and reviewing any debug patches.

### Compile validation before packaging

Install the build dependencies described in the [README](README.md) and the headers/build tree for the exact supported kernel that will run the driver. Resolve all patch conflicts before compiling.

**Always pass the target kernel headers/build-tree path explicitly** for debug validation. Without it, the script defaults to `/lib/modules/$(uname -r)/build`, which belongs to the booted kernel and may not be supported by this driver release. Do not assume the booted kernel is the intended target.

```sh
sh -e ./compile.sh compile /path/to/target/kernel/headers
```

The [compile script](compile.sh) configures the tree, selects the Xe configuration, and builds the kernel modules without installing them. Invoke it with `sh -e` so a failed configure or build command stops execution with a nonzero status; the script's final completion message alone is not proof of success.

**If compilation fails, stop here.** Fix the debug changes and repeat the build until it succeeds. Only then proceed with packaging below. Repeat validation for each supported target kernel you intend to test; a successful build for one kernel does not establish compatibility with another. Runtime testing and the installation-time DKMS build are still required.

### Debian / Ubuntu

After successful compile validation:

```sh
make xe-dkms-deb-pkg
```

The `.deb` package is created in the parent directory.

### RPM-based distributions

After successful compile validation:

```sh
make xe-dkms-rpm-pkg
```

The `.rpm` package is created under `~/rpmbuild/RPMS/x86_64/`.

Package targets clean build outputs and package the source; the locally built `.ko` files are validation artifacts, not replacements for the DKMS build on the test system. If you edit the source after validation, compile it again before packaging.

For successive debug builds, also pass a distinct package build revision, for example `make xe-dkms-deb-pkg BUILD_VERSION=2` or `make xe-dkms-rpm-pkg BUILD_VERSION=2`. This is separate from the source debug counter.

Install the package on a test system with matching kernel headers and reproduce the issue to validate the change. Refer to the main [README](README.md#installation) for installation and verification commands.

Keep temporary diagnostic changes isolated and review them before sharing or merging a package built with them.

## 4. Creating Kernel-Tree Patches

After the debug fix is identified, reviewed, and validated, export the relevant commits as kernel-tree patches. Exclude `src/versions` so the local debug identifier is not included.

### ML patches

For ML submission, preserve the real commit IDs. Set `BASE_COMMIT` to the commit immediately before the series:

```sh
BASE_COMMIT=commit-before-series
mkdir -p /tmp/ml-series
git -C src format-patch --relative --numbered --base="$BASE_COMMIT" \
   --output-directory=/tmp/ml-series "$BASE_COMMIT"..HEAD -- ':(exclude)versions'
```

This creates one numbered patch per commit and keeps each real commit SHA in its patch header. Submit the generated patches with `git send-email /tmp/ml-series/*.patch`.

### XEKMD Backport Patches

For patches intended for `kernel-backport/main`, generate each patch with a zeroed envelope commit ID and a numbered filename:

```sh
COMMIT=commit-to-export
mkdir -p /tmp/xekmd-patches
git -C src format-patch --relative --zero-commit --numbered --base="$COMMIT^" \
   --output-directory=/tmp/xekmd-patches -1 "$COMMIT" -- ':(exclude)versions'
```

Each output is named `0001-<commit-subject>.patch`; its envelope `From` line contains zeros instead of the commit SHA, while author information is preserved. Use a separate output directory for each patch if exporting commits one at a time.

### Applying to `kernel-backport/main`

The generated patches use kernel-tree paths such as `drivers/gpu/drm/xe/`, without `src/`. From a checkout of `kernel-backport/main`, apply them in commit order, listing their filenames explicitly. Replace these examples with the generated filenames:

```sh
git am /tmp/xekmd-patches/0001-first-patch.patch \
    /tmp/xekmd-patches/0001-second-patch.patch
```

Do not rely on wildcard sorting to determine application order: every patch has the same `0001-` prefix.

**Path handling note:** In the export commands above, `git -C src` runs Git from the `src/` directory, while `--relative` emits kernel-tree paths without the `src/` prefix. To apply those patches inside this DKMS repository, use `git am --directory=src`; Git prefixes the target paths during application without modifying the patch files. Do not use that option when applying in a kernel-tree checkout.
