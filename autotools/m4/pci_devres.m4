dnl #
dnl # v6.11-77f79ac8de0f
dnl # PCI: Remove struct pci_devres.enabled status bit
dnl #
AC_DEFUN([AC_PCI_DEVRES_ENABLED_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                pci_devres_enabled=no
                pci_devres_src=no

                for file in drivers/pci/pci.c drivers/pci/pci.h; do
                        if test -r "$LINUX/$file" && grep -q "^struct pci_devres {" "$LINUX/$file"; then
                                pci_devres_src=yes
                                if awk '
                                        /^struct pci_devres \{/ { in_struct = 1 }
                                        in_struct && /unsigned int.*enabled:1;/ { found = 1 }
                                        in_struct && /^\};/ { in_struct = 0 }
                                        END { exit !found }
                                ' "$LINUX/$file"; then
                                        pci_devres_enabled=yes
                                fi
                        fi
                done

                if test "x$pci_devres_src" != "xyes"; then
                        AC_KERNEL_CHECK_SYMBOL_EXPORT([pcim_request_region],
                                [drivers/pci/devres.c], [], [pci_devres_enabled=yes])
                fi

                if test "x$pci_devres_enabled" = "xyes"; then
                        AC_DEFINE(BPM_PCI_DEVRES_ENABLED_PRESENT, 1,
                                [struct pci_devres has the enabled bit; only pcim_enable_device() sets it])
                fi
        ])
])
