# Intel® Graphics Driver Backports for Linux® OS

Contains the backported kernel module source code for Intel® GPUs on various OS distributions and LTS Kernels.

This backport provides early access of discrete GFX functionalities which are not landed in OS Distribution Kernels.

You can create Dynamic Kernel Module Support (DKMS) as well as pre-compiled out-of-tree modules packages, which can be installed on supported OS distributions.

We are using [backport project](https://backports.wiki.kernel.org/index.php/Main_Page) to generate out-of-tree Xe kernel module source codes.

## Contents

- [Changelog](#changelog)
- [Prerequisite](#prerequisite)
- [Dependencies](#dependencies)
- [Known Constraints / Limitations](#known-constraints--limitations)
- [Package creation](#package-creation)
- [Installation](#installation)
- [Verification](#verification)
- [Uninstallation](#uninstallation)
- [Compiling Code](#compiling-code)
- [Debugging](#debugging)

## Changelog

See [changelog.md](changelog.md) for release history and included changes.

## Prerequisite
Install the required build dependencies for your distribution:

| Distribution | Package type | Packages | Install command |
|---|---|---|---|
| Ubuntu / Debian | DEB | `automake`, `dkms`, `make`, `debhelper`, `devscripts`, `dh-dkms` | `sudo apt install automake dkms make debhelper devscripts dh-dkms` |
| Red Hat / RHEL | RPM | `automake`, `dkms`, `make`, `rpm-build`, `rpmdevtools`, `bison`, `flex` | `sudo dnf install automake dkms make rpm-build rpmdevtools bison flex` |

## Dependencies

 These drivers have a dependency on Intel_ GPU firmware and a few more kernel mode drivers may be needed based on specific use cases, platforms, and distributions. The source code of additional drivers should be available at [Intel GPU](https://github.com/intel-gpu)

- [Intel_ GPU firmware](https://github.com/intel-gpu/intel-gpu-firmware) - Firmware required by Intel_ GPUs.

Each project is tagged consistently, so when pulling these repos, pull the same tag.

## Known Constraints / Limitations

### AER Ownership

- On kernels that do not report AER ownership, add `pcie_ports=native` to the kernel command line so the OS handles AER errors correctly.

### DMA-VRAM-PINNING
The dmem cgroup controller used to bound pinned device memory was introduced in kernel v6.14 and may not be available on some older OSV kernels. Without it, there is no way to stop a single unprivileged client from pinning VRAM (e.g. via dma-buf) until the region is exhausted, starving every other client — a denial-of-service.

To mitigate this on older kernels, the driver can enforce a per-region limit that caps the amount of VRAM that may be pinned through `dma-buf` as a percentage of each region's size.

#### Mitigation Behavior & Constraints
Because this is a standalone driver-level mitigation, it operates with the following capabilities and boundaries:
* **Global Enforcement:** It successfully protects the hardware by acting as a global, per-region cap. However, it *cannot* perform fine-grained memory accounting per container or per process.
* **Hard Rejection:** It effectively prevents total VRAM starvation by drawing a strict line. If a client attempts to pin memory that breaches the configured threshold, the allocation is immediately rejected with an `-ENOSPC` error, which can be resolved by increasing the limit using the below parameter.

#### xe module parameter: `pin_vram_percent`
Caps how much of each VRAM region may be **pinned via dma-buf**.

#### Values
- **Driver default: `0`** (unlimited or limit disabled).
- Percentage (`0`-`100`) of each VRAM region that may be dma-buf pinned.

#### Usage
Set it at module load time:

```sh
modprobe xe pin_vram_percent=50   # allow up to 50% of each region
```

Read the current value:

```sh
cat /sys/module/xe/parameters/pin_vram_percent
```

*(Note: The limit is applied once when the driver initializes; you must reload the xe module to apply changes.)*

## Package creation

### Dynamic Kernel Module Support(DKMS)

Build the DKMS package for your distribution:

| Distribution | Package type | Build command | Generated package |
|---|---|---|---|
| Debian / Ubuntu | DEB | `./compile.sh configure`<br>`make xe-dkms-deb-pkg` | Parent folder<br>`intel-xe-dkms_<kernel-version>-<release-version>+i1-1_all.deb`<br>Example: `intel-xe-dkms_6.14.0.37-6.17.13.62.260409.9+i102-1_all.deb` |
| Red Hat / RHEL | RPM | `./compile.sh configure`<br>`make xe-dkms-rpm-pkg` | `~/rpmbuild/RPMS/x86_64/`<br>`intel-xe-dkms-<kernel-version>-<release-version>.<distro-suffix>.x86_64.rpm`<br>Example: `intel-xe-dkms-6.12.0.124.8.1-6.17.13.54.260409.4.1.el10_1.x86_64.rpm` |

**Note:** You can check the expected package version and name before building:

```
$ make show-version
```
## Installation

Install the package for your distribution:

| Distribution | Package type | Install command |
|---|---|---|
| Ubuntu / Debian | DEB | `sudo dpkg -i intel-xe*.deb` |
| Red Hat / RHEL | RPM | `sudo rpm -ivh ~/rpmbuild/RPMS/x86_64/intel-xe-dkms-*.rpm` |

Reboot the device after installation of all packages.
```
$ sudo reboot
```

## Verification
For verification, Please grep **backport** from dmesg after reboot. You should see something like below
```
$ sudo dmesg |grep -i backport
[....] XE Backport init, Module is backported from xebr_v7.1.4.72_260728.53
```

You can also check the Xe module version with below method:
```
$ cat /sys/module/xe/version
```

Example:
```
$ cat /sys/module/xe/version
backported from (1661d9b2c) using backports xebr_v7.1.4.72_260728.53 for 7.0.0-38-generic Kernel
```
From the above example, we can extract version from which dkms was created(xebr_v7.1.4.72_260728.53).

## Uninstallation

| Distribution | Package type | Uninstall command |
|---|---|---|
| Ubuntu / Debian | DEB | `sudo dpkg -r intel-xe*` |
| Red Hat / RHEL | RPM | `sudo rpm -e intel-xe-dkms*` |

Reboot the device after uninstallation of all packages.
```
$ sudo reboot
```

## Compiling Code

Autotools have a series of commands to generate configure and Makefile. In order
to make life simple, use script created. 

Command to compile:

`
./compile.sh compile <headers-path>
`

By default, "<headers-path>" is set as standard headers path of currently booted kernel i.e., /lib/modules/<uname -r>/build


Note: For adding new M4 Files, please follow [Rules](src/docs/README_rules.md) Document.

## Debugging

For applying temporary debug patches and building a test DKMS package, see the [DKMS Debug Guide](dkms-debug-guide.md).

