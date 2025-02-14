
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

Note: 
1. Patches present in base will be removed once merged in mainline kernel.
2. Patches present in features are dynamic in nature, they may change frequently and removed once merged in drm-tip.
3. Patches present in features will use prelim uapi to aviod conflict in updates, once patches are merged in drm-tip, uapi will change from prelim to normal.
4. prelim upai will be maintained at [drm-uapi-helper](https://github.com/intel-gpu/drm-uapi-helper/tree/xe).

# Usage
backport.sh < options >

|options:| | |
|-- |--|--| 
|1. |create-tree| Create kernel tree based on given option <base/features>|
|2. |delete-tree| Delete the tree|
|3. |reset-tree| Delete the existing tree and re-create it|
|4. |override| Overrides existing tree|


# License

This work is a subset of the Linux kernel as such we keep the kernel's
Copyright practice. Some files may have their own copyright and in those
cases the license is mentioned in the file.
