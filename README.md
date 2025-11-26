# xekmd-backports

Repository for Intel® Graphics Driver (Xe KMD) backports and development branches.

## Overview

This repository contains multiple branches for Intel® Graphics Driver (Xe) backports targeting different kernel versions. The repository is structured to support kernel backports, out-of-tree (OOT) builds, and release management.

## Repository Structure

### Workflow Overview

**kernel-backport → oot-backport → releases**

### Branches

| Kernel Backport Branches | OOT Backport Branch | Release Branch |
|---------------------------|---------------------|----------------|
| **[kernel-backport/main](https://github.com/intel-gpu/xekmd-backports/tree/kernel-backport/main)** ([README](https://github.com/intel-gpu/xekmd-backports/blob/kernel-backport/main/README.md)) <br> *Status:* **Active** (Recommended) <br> *Kernel:* v6.17+ <br> *Description:* Primary backport branch with in-tree patches. Latest features: PMU, hwmon, SR-IOV, EU debugging, Xe2 HPG. Can be used for full kernel builds and DKMS generation | **[oot-backport/main](https://github.com/intel-gpu/xekmd-backports/tree/oot-backport/main)** ([README](https://github.com/intel-gpu/xekmd-backports/blob/oot-backport/main/README.md)) <br><br> *Status:* **Active** <br><br> *Description:* Processes kernel-backport branches and applies compatibility layers, DKMS support, and build configurations | **[releases/main](https://github.com/intel-gpu/xekmd-backports/tree/releases/main)** ([README](https://github.com/intel-gpu/xekmd-backports/blob/releases/main/README.md)) <br><br> *Status:* **Active** <br><br> *Description:* Final generated out-of-tree xe and other required modules for DKMS generation |
| **[kernel-backport/main_6.14](https://github.com/intel-gpu/xekmd-backports/tree/kernel-backport/main_6.14)** ([README](https://github.com/intel-gpu/xekmd-backports/blob/kernel-backport/main_6.14/README.md)) <br> *Status:* **Active** <br> *Kernel:* v6.14 <br> *Description:* In-tree backport patches. SR-IOV backports from v6.14-v6.17, VFIO migration support | | |
| **[kernel-backport/main_6.11](https://github.com/intel-gpu/xekmd-backports/tree/kernel-backport/main_6.11)** ([README](https://github.com/intel-gpu/xekmd-backports/blob/kernel-backport/main_6.11/README.md)) <br> *Status:* **Frozen** <br> *Kernel:* v6.11 <br> *Description:* In-tree backport patches. No longer receiving updates | | |

**Management Branch:** [master](https://github.com/intel-gpu/xekmd-backports/tree/master) - Repository management, documentation, setup scripts, and contribution guidelines

**Note:** See each branch's README for detailed information and instructions.

## Quick Start

### Using Git Worktrees (Recommended)

The repository includes a `setup-worktree.sh` script to manage multiple branches efficiently:

```bash
# Create all worktrees (kernel-backport, oot-backport, releases)
./setup-worktree.sh create-worktree

# Create only kernel-backport worktree and generate base kernel
./setup-worktree.sh kernel-backport-only

# Create only releases worktree
./setup-worktree.sh oot-release-only

# List current worktrees
./setup-worktree.sh list-worktree

# Clean up all worktrees
./setup-worktree.sh clean-worktree
```

After running `create-worktree`, you'll have:
- `kernel-backport/` - Working directory for kernel-backport/main (input branch)
- `oot-backport/` - Working directory for oot-backport/main (processing branch)
- `releases/` - Working directory for releases/main (output branch)

### Manual Branch Checkout

```bash
# Check out a specific kernel version
git checkout kernel-backport/main        # Latest (6.17+)
git checkout kernel-backport/main_6.14   # Kernel 6.14
git checkout kernel-backport/main_6.11   # Kernel 6.11 (frozen)
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our contribution process and code of conduct.

All contributions must be signed off according to the Developer Certificate of Origin (DCO). Add a sign-off line to your commits:

```bash
git commit -s -m "Your commit message"
```

## License

This work is a subset of the Linux kernel and follows the kernel's licensing. See individual files for specific copyright and license information. The kernel is licensed under GPL-2.0.

## Support and Community

- **Security Issues**: See [SECURITY.md](SECURITY.md)
- **Code of Conduct**: See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---
