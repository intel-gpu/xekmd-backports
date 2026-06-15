# Intel® Graphics Driver Backports for Linux® OS

Contains the backported kernel module source code for Intel® GPUs on various OS distributions and LTS Kernels.

This backport provides early access of discrete GFX functionalities which are not landed in OS Distribution Kernels.

You can create Dynamic Kernel Module Support (DKMS) as well as pre-compiled out-of-tree modules packages, which can be installed on supported OS distributions.

We are using [backport project](https://backports.wiki.kernel.org/index.php/Main_Page) to generate out-of-tree xe kernel module source codes.

## Prerequisite
We have dependencies on the following packages
### Ubuntu Supported OS Kernel/Distribution
  - automake
  - dkms
  - make
  - debhelper
  - devscripts

```
$ sudo apt install automake dkms make debhelper devscripts
```

### Redhat Supported OS Kernel/Distribution
  - automake
  - dkms
  - make
  - rpm-build
  - rpmdevtools
  - bison
  - flex

```
$ sudo dnf install automake dkms make rpm-build rpmdevtools bison flex
```

## Dependencies

 These drivers have a dependency on Intel_ GPU firmware and a few more kernel mode drivers may be needed based on specific use cases, platforms, and distributions. The source code of additional drivers should be available at [Intel GPU](https://github.com/intel-gpu)

- [Intel_ GPU firmware](https://github.com/intel-gpu/intel-gpu-firmware) - Firmware required by Intel_ GPUs.

Each project is tagged consistently, so when pulling these repos, pull the same tag.

## Package creation

### Dynamic Kernel Module Support(DKMS)

Creating xe DKMS packages

```
$ make <DKMS Package Target>
```

```
Example:
	$./compile.sh configure
	$ make xe-dkms-deb-pkg

Generated package name:
	intel-xe-dkms_<kernel-version>-<release-version>+i1-1_all.deb
	Example: intel-xe-dkms_6.12.0.124.8.1-6.17.13.49.260409.4+i1-1_all.deb
```
Above command will create Debian package in parent folder. **intel-xe-dkms_\<kernel-version\>-\<release-version\>+i1-1_all.deb**

```
Example:
	$ ./compile.sh configure
	$ make xe-dkms-rpm-pkg

Generated package name:
	intel-xe-dkms-<kernel-version>-<release-version>.<distro-suffix>.x86_64.rpm
	Example: intel-xe-dkms-6.12.0.124.8.1-6.17.13.54.260409.4.1.el10_1.x86_64.rpm
```
Above command will create RPM package in `~/rpmbuild/RPMS/x86_64/` directory.

**Note:** You can check the expected package version and name before building:
```
$ make show-version
```
## Installation and verification

### Ubuntu/Debian
```
$ sudo dpkg -i intel-xe*.deb
```

### Redhat
```
$ sudo rpm -ivh ~/rpmbuild/RPMS/x86_64/intel-xe-dkms-*.rpm
```

Reboot the device after installation of all packages.
```
$ sudo reboot
```
For verification, Please grep **backport** from dmesg after reboot. You should see something like below
```
$ sudo dmesg |grep -i backport
[.....] COMPAT: Backport init, Module is backported from xe-586
```
## Uninstallation

### Ubuntu/Debian
```
$ sudo dpkg -r intel-xe*
```

### Redhat
```
$ sudo rpm -e intel-xe-dkms*
```

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
