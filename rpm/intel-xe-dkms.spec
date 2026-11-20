Name:           intel-xe-dkms
Version:        6.14.0.37
Release:        7.3.0.261118.5.1
Summary:        Intel Xe DRM Driver
License:        MIT/GPL
Packager:       Intel Linux Graphics Team <linux-graphics@intel.com>
BuildArch:      x86_64

%define __os_install_post %{nil}
%define debug_package %{nil}


Requires: dkms, kernel-devel, gcc, make, flex, bison
Requires: autoconf, automake

Provides: xe-modules

%description
Out of tree xe driver.

%build

%install
mkdir -p %{buildroot}/usr/src/%{name}-%{version}
cp -r %{_sourcedir}/src %{buildroot}/usr/src/%{name}-%{version}/ 2>/dev/null || true
cp -r %{_sourcedir}/m4 %{buildroot}/usr/src/%{name}-%{version}/ 2>/dev/null || true
cp -r %{_sourcedir}/debian %{buildroot}/usr/src/%{name}-%{version}/ 2>/dev/null || true
cp %{_sourcedir}/Makefile* %{_sourcedir}/configure* %{_sourcedir}/aclocal.m4 %{buildroot}/usr/src/%{name}-%{version}/ 2>/dev/null || true
cp %{_sourcedir}/AUTHORS %{_sourcedir}/ChangeLog %{_sourcedir}/COPYING %{_sourcedir}/INSTALL %{_sourcedir}/NEWS %{_sourcedir}/README.md %{_sourcedir}/oot-build.sh %{buildroot}/usr/src/%{name}-%{version}/ 2>/dev/null || true
cp -r %{_sourcedir}/src/backport-include %{buildroot}/usr/src/%{name}-%{version}/ 2>/dev/null || true
cp -r %{_sourcedir}/src/include %{buildroot}/usr/src/%{name}-%{version}/ 2>/dev/null || true
cp %{_sourcedir}/rpm/%{name}.dkms.conf %{buildroot}/usr/src/%{name}-%{version}/dkms.conf 2>/dev/null || true

%post
update_initramfs() {
kver="$1"
echo -e "Creating initramfs for :$kver"
if [ ! -e /boot/vmlinuz-$kver ]; then
echo -e "Unable to create initramfs for :$kver (kernel image not found)"
return 0
fi
if command -v depmod >/dev/null 2>&1; then
depmod -a "$kver"
fi
if command -v dracut >/dev/null 2>&1; then
echo -e "Using dracut"
dracut -f --kver "$kver" || echo -e "dracut failed for :$kver"
elif command -v update-initramfs >/dev/null 2>&1; then
echo -e "Using update-initramfs"
update-initramfs -u -k "$kver" || echo -e "update-initramfs failed for :$kver"
elif command -v mkinitrd >/dev/null 2>&1; then
if [ "$MKINITRD_DONE" != "1" ]; then
echo -e "Using mkinitrd"
mkinitrd || echo -e "mkinitrd failed"
MKINITRD_DONE="1"
fi
else
echo -e "No initramfs tool (dracut/update-initramfs/mkinitrd) found, skipping initramfs for :$kver"
fi
}
dkms add -m intel-xe-dkms -v 6.14.0.37 --rpm_safe_upgrade || true
MKINITRD_DONE="0"
INITRD_KERNELS=""
for i in /lib/modules/[5-7]*; do
H="$i/build"
K=$(echo $i | cut -d '/' -f 4)
if [ -d /usr/src/kernels/$K ]; then
KDIR=/usr/src/kernels/$K
elif [ -d $H ]; then
KDIR=$H
else
KDIR=""
fi
if [ -n "$KDIR" ]; then
dkms build -m intel-xe-dkms -v 6.14.0.37 --kernelsourcedir "$KDIR" --rpm_safe_upgrade || true
dkms install --force -m intel-xe-dkms -v 6.14.0.37 --kernelsourcedir "$KDIR" --rpm_safe_upgrade || true
INITRD_KERNELS="$INITRD_KERNELS $K"
else
echo "SKIP DKMS Installation: kernel headers not available for $K"
fi
done
for K in $INITRD_KERNELS; do
update_initramfs "$K"
done

%preun
update_initramfs() {
kver="$1"
echo -e "Creating initramfs for :$kver"
if [ ! -e /boot/vmlinuz-$kver ]; then
echo -e "Unable to create initramfs for :$kver (kernel image not found)"
return 0
fi
if command -v depmod >/dev/null 2>&1; then
depmod -a "$kver"
fi
if command -v dracut >/dev/null 2>&1; then
echo -e "Using dracut"
dracut -f --kver "$kver" || echo -e "dracut failed for :$kver"
elif command -v update-initramfs >/dev/null 2>&1; then
echo -e "Using update-initramfs"
update-initramfs -u -k "$kver" || echo -e "update-initramfs failed for :$kver"
elif command -v mkinitrd >/dev/null 2>&1; then
if [ "$MKINITRD_DONE" != "1" ]; then
echo -e "Using mkinitrd"
mkinitrd || echo -e "mkinitrd failed"
MKINITRD_DONE="1"
fi
else
echo -e "No initramfs tool (dracut/update-initramfs/mkinitrd) found, skipping initramfs for :$kver"
fi
}
MKINITRD_DONE="0"
INITRD_KERNELS=""
for i in /var/lib/dkms/intel-xe-dkms/6.14.0.37/[^a-zA-Z]*; do
if [[ $i = *^* ]]; then continue; fi
K=$(echo $i | cut -d '/' -f 7)
if [ -d /usr/src/kernels/$K ]; then
KDIR=/usr/src/kernels/$K
elif [ -d /lib/modules/$K/build ]; then
KDIR=/lib/modules/$K/build
else
KDIR=""
fi
if [ -n "$KDIR" ]; then
dkms uninstall -m intel-xe-dkms -v 6.14.0.37 --kernelsourcedir "$KDIR" --rpm_safe_upgrade || true
else
dkms uninstall -m intel-xe-dkms -v 6.14.0.37 -k $K --rpm_safe_upgrade || true
fi
INITRD_KERNELS="$INITRD_KERNELS $K"
done
for K in $INITRD_KERNELS; do
update_initramfs "$K"
done
dkms remove -m intel-xe-dkms -v 6.14.0.37 --all --rpm_safe_upgrade || true

%files
/usr/src/%{name}-%{version}/
