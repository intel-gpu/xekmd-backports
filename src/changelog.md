This page summarizes the major features in each release of backported kernel module source code for Xe drivers and provides links to additional information.

## 🗝️ Legend & Conventions
- Patchwork: Tracks submitted patches or series which are part of Mailing List (ML). With their respective revisions, such as v1 or v4.
- linux-next: Links to the commit merged into the linux-next integration tree.
- xe-next (drm-xe-next): Links to the commit merged into the Xe driver integration tree.
- oot-backport: Uses the SHA and commit link from oot-backport/main.

| Release version | Source | SHA | Commit header |
|---|---|---|---|
| `xebr_v7.1.4.71_260728.53` | | | |
| | oot-backport/main | [`62ffcb3f4`](<https://github.com/intel-gpu/xekmd-backports/commit/62ffcb3f4ce70bb18a57c9017e656eed81082359>) | gentree: Allow uncommitted changes in generated kernel trees |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/177598/#rev3>) | &#91;TEMP&#93; drm/xe/pf: Program LMTT directory pointer from each GT's init path |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/177598/#rev3>) | &#91;TEMP&#93; drm/xe/pf: Use multicast writes for early-generation LMTT config |
| | xe-next | [`e30553655`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/e305536554790e06876dd4e4f854c97d1353aa79>) | drm/xe/guc: Demote uncorrectable local error log on CRI |
| |  | Backport-only change | Backport-only: Add Ocode firmware linkage for Xe module |
| `xebr_v7.1.4.68_260728.52` | | | |
| | oot-backport/main | [`4e6e5aa5f`](<https://github.com/intel-gpu/xekmd-backports/commit/4e6e5aa5f654aaea8a43be46d2b7188ee7db44f2>) | gentree: Derive release tag from backport kernel and latest xeb tag |
| | oot-backport/main | [`64139971b`](<https://github.com/intel-gpu/xekmd-backports/commit/64139971bb2014e9829614c2c37d5bb53bd8360a>) | auto-tag: generate xeb tags from kernel-backport head with stream-aware revisioning |
| | linux-next | [`d7bc407b3`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d7bc407b38090e908d2b63560bd3c5c44185e56f>) | drm/xe/xe_late_bind_fw: Enable late binding support for CRI |
| | linux-next | [`85e65b9b9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=85e65b9b9d627e955761c67001057c2516b97bde>) | drm/xe/xe_late_bind_fw: Add string mappings of status codes |
| | linux-next | [`918e85a4f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=918e85a4f597eac1f566bfc9f315d18def8ec8d3>) | drm/xe/xe_late_bind_fw: Add support to load Ocode firmware |
| | linux-next | [`b3a6e42af`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b3a6e42af57df74c19093d32a6fa3a3fa8b5b592>) | drm/xe/xe_late_bind_fw: Convert late bind flag to mask |
| | linux-next | [`d7bc407b3`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d7bc407b38090e908d2b63560bd3c5c44185e56f>) | drm/xe/xe_late_bind_fw: Enable late binding support for CRI |
| | linux-next | [`3e4b2a634`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3e4b2a6349ed7258057fa95a1e58730615703dae>) | drm/xe/xe_late_bind_fw: Fix firmware leak on missing manifest entry |
| | linux-next | [`6569aa662`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=6569aa6628799976b1c857afe8793c4fe70afb68>) | drm/xe/xe_late_bind_fw: Refactor pm flow |
| `xebr_v7.1.4.66_260728.53` | | | |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/757598/?series=175385&rev=1>) | &#91;TEMP&#93;: platform/x86/intel/pmt: Fix NULL dereference when reading crashlog data |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/762356/?series=176683&rev=1>) | &#91;TEMP&#93;: platform/x86/intel/pmt: Notify userspace when crashlogs complete |
| | linux-next | [`3678e39c6`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3678e39c6aaeb9aa380c7357b24f7d55955543f8>) | platform/x86/intel/vsec: Fix inverted walk_header() test in get_features() |
| `xebr_v7.1.4.65_260728.52` | | | |
| |  | Backport-only change | &#91;TEMP&#93; drm/xe/guc: Update recommended GuC version for CRI |
| `xebr_v7.1.4.64_260728.51` | | | |
| | oot-backport/main | [`f7dbb962c`](<https://github.com/intel-gpu/xekmd-backports/commit/f7dbb962c30b2955b5b81239c45d83fdc17dfdf1>) | drm/xe: Backport fdinfo support for kernels without drm_show_fdinfo |
| | linux-next | [`126c4c538`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=126c4c5388f9311a390b9b254a835b0cf0f55331>) | drm/xe/oa: Zero OA buffer at allocation |
| `xebr_v7.1.4.63_260728.50` | | | |
| | oot-backport/main | [`a2149669c`](<https://github.com/intel-gpu/xekmd-backports/commit/a2149669cf4a03f2bb5b442124f62fbb9b734109>) | drm/gem: fix structure member ordering mismatch |
| | oot-backport/main | [`730d22abe`](<https://github.com/intel-gpu/xekmd-backports/commit/730d22abee66084770b1b3a3902bc44732d83711>) | compat/dma-resv: Fix refcount underflow on imported buffers |
| | oot-backport/main | [`a79b6911a`](<https://github.com/intel-gpu/xekmd-backports/commit/a79b6911ab6f5eda804362602e5a7a0ce3af8096>) | Reapply "Drop drm_pagemap_put guard" and "Fix madvise ops generation" |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/760212/?series=176134&rev=1>) | &#91;TEMP&#93;: vfio/xe: Add CRI and NVL device IDs |
| `xebr_v7.1.4.62_260728.49` | | | |
| | ML v4 | [Patchwork](<https://patchwork.freedesktop.org/series/175996/#rev4>) | &#91;TEMP&#93;: drm/xe: Disable scheduling early on FD close to avoid CAT error cascade |
| | ML v4 | [Patchwork](<https://patchwork.freedesktop.org/series/175996/#rev4>) | &#91;TEMP&#93;: drm/xe: Read scheduler message opcode under lock |
| | ML v4 | [Patchwork](<https://patchwork.freedesktop.org/series/175996/#rev4>) | &#91;TEMP&#93;: drm/xe: Synchronously wait for queue kill on FD close |
| | linux-next | [`d3f1b058a`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d3f1b058a77d1754d469ea4eaf43e754d43cdc4c>) | &#91;TEMP&#93;: drm/xe/ggtt: invalidate engine GGTT TLBs for multi-queue GTs |
| `xebr_v7.1.4.60_260728.48` | | | |
| | oot-backport/main | [`f641b643d`](<https://github.com/intel-gpu/xekmd-backports/commit/f641b643d16468b4c897d48cb5a3a342a470bb31>) | Revert "Drop drm_pagemap_put guard" and "Fix madvise ops generation" |
| | oot-backport/main | [`89ebd975e`](<https://github.com/intel-gpu/xekmd-backports/commit/89ebd975eff7fc7a42535806ae9ff2882346f978>) | compat/drm_gpuvm_madvise: Fix madvise ops generation |
| | oot-backport/main | [`f75264dce`](<https://github.com/intel-gpu/xekmd-backports/commit/f75264dce075ab58b866cb624c0e88e1c6ecf963>) | autotools/m4: Drop drm_pagemap_put guard |
| |  | Backport-only change | &#91;TEMP&#93; drm/xe/guc: Update recommended GuC version for CRI |
| `xebr_v7.1.4.59_260728.47` | | | |
| | linux-next | [`ee460b885`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ee460b8855d4a419a204bb68d91675e33b0c0d61>) | drm/xe/ggtt: fault on unmapped GGTT for multi-queue platforms |
| | linux-next | [`d3f1b058a`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d3f1b058a77d1754d469ea4eaf43e754d43cdc4c>) | drm/xe/ggtt: invalidate engine GGTT TLBs for multi-queue GTs |
| | linux-next | [`0f0a5aba8`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0f0a5aba875992c4d0aaf8c6178550557fa38ce2>) | drm/xe/tlb_inval: add xe_tlb_inval_ggtt_full() GGTT invalidation helper |
| `xebr_v7.1.4.58_260728.46` | | | |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/761238/?series=176414&rev=1>) | &#91;TEMP&#93; drm/xe: Extend Wa_16030224309 to graphics version 35.11 |
| | linux-next | [`3abf37f5a`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3abf37f5a6c1ee238ffaa34e75e9ecb0ee2db4a4>) | drm/xe/xe3p_lpg: Add support for Wa_16030224309 |
| | drm-tip-eudebug | [`e67781291`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/e67781291ae461975057a03d678023f43127b704>) | drm/xe/eudebug: Mark guc contexts as debuggable |
| `xebr_v7.1.4.57_260728.45` | | | |
| | oot-backport/main | [`6273452f4`](<https://github.com/intel-gpu/xekmd-backports/commit/6273452f43a6f600778acb0264c7d2a4fcb64ba2>) | drm/xe: Allow subsequent legacy devcoredumps safely |
| `xebr_v7.1.4.57_260728.44` | | | |
| | oot-backport/main | [`ad1ce14ae`](<https://github.com/intel-gpu/xekmd-backports/commit/ad1ce14aec220aa33ae716533c86b52b452d5835>) | Fix drm show_fdinfo probe failing issue |
| `xebr_v7.1.4.57_260728.43` | | | |
| | oot-backport/main | [`4a148767d`](<https://github.com/intel-gpu/xekmd-backports/commit/4a148767d4da8ff9b77170964eb57fac1f1ee5ee>) | patches: fix hunk offsets to resolve hunk failures |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/175996/#rev3>) | &#91;TEMP&#93;: drm/xe: Disable scheduling early on FD close to avoid CAT error cascade |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/175996/#rev3>) | &#91;TEMP&#93;: drm/xe: Read scheduler message opcode under lock |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/175996/#rev3>) | &#91;TEMP&#93;: drm/xe: Synchronously wait for queue kill on FD close |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/172710/#rev3>) | &#91;TEMP&#93;: drm/xe: Separate drm-ras netlink data from device and firmware RAS state |
| | linux-next | [`505f803cf`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=505f803cfdea3a5f75d5f3b049a39024f966280f>) | drm/xe/ras: Fix sysctrl and drm-ras discrepancy |
| | ML v14 | [Patchwork](<https://patchwork.freedesktop.org/patch/760018/?series=160717&rev=14>) | &#91;TEMP&#93; drm/xe/vsec: Support survivability mode for CRI |
| | linux-next | [`0b3aec1e9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0b3aec1e9b6f71840f579f202c978777629b9e3f>) | drm/xe/sysctrl: Add mailbox control state to error messages |
| | linux-next | [`f0a444778`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f0a4447789ef28ba1aded2db19543d69c640b5e5>) | drm/xe/sysctrl: Fix mailbox header handling |
| | linux-next | [`3215ff2b7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3215ff2b71b7b8117657019ec3b6b64e585563c6>) | drm/xe/sysctrl: Improve firmware response error logging |
| | linux-next | [`081b99368`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=081b993689d3510dbdc2d83f6956441612e0d02f>) | drm/xe/sysctrl: Log group and command ID on mailbox failure |
| | linux-next | [`e192be856`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=e192be8566a02cb3f8b7d4707cc6e719c2ed4536>) | drm/xe/sysctrl: Make sysctrl_read_frame() void |
| | linux-next | [`75e8c0bbf`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=75e8c0bbf235ac1288421b82acc7064460bc7282>) | drm/xe/sysctrl: Make sysctrl_write_frame() void |
| | linux-next | [`10b59a4c3`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=10b59a4c3196cf5ccb27adc0abb8e32b9cee5acc>) | drm/xe/sysctrl: Replace FIELD_GET() with REG_FIELD_GET() |
| | linux-next | [`d511f9d1c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d511f9d1c1cf0422bfd008e81956734b6bf9be2a>) | drm/xe/sysctrl: Return error codes from sysctrl_wait_bit_clear() |
| | linux-next | [`026bd0e21`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=026bd0e216077ea04c72c2f90261fba7b305d409>) | drm/xe/sysctrl: Return error codes from sysctrl_wait_bit_set() |
| | linux-next | [`a98308558`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a9830855883da2372b21dbee95c27d4694b8e5d6>) | drm/xe/sysctrl: Use xe_assert() for payload size validation |
| |  | Backport-only change | README: Update Frozen Branches |
| `xebr_v7.1.4.54_260728.42` | | | |
| | oot-backport/main | [`b754aedd6`](<https://github.com/intel-gpu/xekmd-backports/commit/b754aedd6b3909aa869c327f10ac31ca683b50d0>) | backport-include/linux: Add fallback for missing str_up_down helper() api |
| `xebr_v7.1.4.54_260728.41` | | | |
| | oot-backport/main | [`220dcb822`](<https://github.com/intel-gpu/xekmd-backports/commit/220dcb822386285eff8cb6f9d1780b382f42d66f>) | backport-include/drm: Fix inverted gem_prime_mmap condition |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/759600/?series=175989&rev=1>) | &#91;TEMP&#93; drm/xe/cri: Implement workaround Wa_15020021844 |
| `xebr_v7.1.4.53_260728.40` | | | |
| | oot-backport/main | [`112c64d19`](<https://github.com/intel-gpu/xekmd-backports/commit/112c64d19ce3805eec93b7886d21fe9d523970d1>) |  DKMS: RPM: Fix initramfs creation logic in post scripts |
| `xebr_v7.1.4.53_260728.39` | | | |
| | oot-backport/main | [`814e688be`](<https://github.com/intel-gpu/xekmd-backports/commit/814e688bed263071e4a8fef2d5e727264073f02e>) | Revert "compat/dma-resv: Fix refcount underflow on imported buffers" |
| `xebr_v7.1.4.53_260728.38` | | | |
| | oot-backport/main | [`053d0f312`](<https://github.com/intel-gpu/xekmd-backports/commit/053d0f31250a205e73ce31ca55e1c79c3016db80>) | README: Refine DMA-VRAM-PINNING documentation |
| | oot-backport/main | [`8323d5779`](<https://github.com/intel-gpu/xekmd-backports/commit/8323d5779948d31e6cdeb369e374f2093c1e48d6>) | drm/xe: Change default VRAM pin limit to 0 |
| | oot-backport/main | [`10f7fba01`](<https://github.com/intel-gpu/xekmd-backports/commit/10f7fba01bba2165d5648234170970808172fb64>) | compat/dma-resv: Fix refcount underflow on imported buffers |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/758679/?series=175785&rev=1>) | &#91;TEMP&#93; drm/xe/cri: Set downstream access to L3 class 3 and write-back |
| `xebr_v7.1.4.52_260728.37` | | | |
| | oot-backport/main | [`864e35510`](<https://github.com/intel-gpu/xekmd-backports/commit/864e355102f34954487b200cf08325b296165635>) | README: Add module parameter requirement for vram pinning |
| | oot-backport/main | [`62fb43c05`](<https://github.com/intel-gpu/xekmd-backports/commit/62fb43c05fe3ab3a0183d34280ecefcc8b35242f>) | drm/xe: print full backports tag in init logs |
| | linux-next | [`cb4afddf9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=cb4afddf9e018a83fec8614d8e337d313871569f>) | drm/xe/lrc: document sentinel and make CTX_TIMESTAMP read TOCTOU-safe |
| `xebr_v7.1.4.51_260728.36` | | | |
| |  | Backport-only change | TEMP mei: csc: disable runtime allow |
| | linux-next | [`baafc300c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=baafc300cd079a5210c1e70e5ea3d93518e40b38>) | drm/xe/nvm: add system controller region |
| | linux-next | [`200c32e3c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=200c32e3cd53132fbf99f1e2a5751f556755cf6d>) | mtd: mtd_intel_dg: reset poll counter for each erase |
| | linux-next | [`682b943f1`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=682b943f154707ab9c1d409c96910b64e38729c7>) | drm/xe/cri: Add new PCI ID |
| `xebr_v7.1.4.49_260728.35` | | | |
| | oot-backport/main | [`9b2d7ef5e`](<https://github.com/intel-gpu/xekmd-backports/commit/9b2d7ef5ecb721d03f1a463d4b0e8c7095d07f62>) | drm/xe: Reset coredump state for legacy devcoredump API |
| | xe-next | [`3fc93d311`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/3fc93d311249d5ad969a520dd3aae73bc007d431>) | drm/xe/xe3p: Force non-compressible memory reads to 256B overfetches |
| `xebr_v7.1.4.48_260728.34` | | | |
| | oot-backport/main | [`0d2d4f806`](<https://github.com/intel-gpu/xekmd-backports/commit/0d2d4f80674c449dad7e7a7c88c64e39fe654df5>) | xe/i2c: gate xe_i2c on i2c-designware Xe backport availability |
| `xebr_v7.1.4.48_260728.33` | | | |
| | oot-backport/main | [`40db4dc4c`](<https://github.com/intel-gpu/xekmd-backports/commit/40db4dc4c709e5f58d719a6d6c6dd2c5eea0c158>) | patches: fix hunk offsets to resolve hunk failures |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/172710/#rev3>) | &#91;TEMP&#93;: drm/xe: Separate drm-ras netlink data from device and firmware RAS state |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/172710/#rev3>) | &#91;TEMP&#93;: drm/xe/xe_ras: Add function to get maximum pages firmware can store |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/172710/#rev3>) | &#91;TEMP&#93;: drm/xe/xe_ras: Add support to query page offline queue and list |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/172710/#rev3>) | &#91;TEMP&#93;: drm/xe/xe_ras: Handle page offline requests for device memory ecc errors |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/172710/#rev3>) | &#91;TEMP&#93;: drm/xe/xe_ras: Track offlined pages by firmware to avoid duplicates |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/172710/#rev3>) | &#91;TEMP&#93;: drm/xe/xe_ttm_vram: Report max_pages reported by firmware to userspace |
| `xebr_v7.1.4.47_260728.32` | | | |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Add helpers to validate thermal sensor readings |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Add platform-aware VRAM thermal channel support |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Cache temperature availability to reduce probe time |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Consolidate temperature sensor availability checks |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Decode CRI temperature registers as IEEE-754 |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Decode mailbox temperature as sign-magnitude |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Detect unavailable PCIe thermal sensors |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Fix memory controller thermal data handling |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Handle pcode read failures of xe_hwmon_pcode_rmw_power_limit |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Handle unavailable memory controller sensors |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Update PCIE temperature sensor offset for CRI |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: Update memory controller temperature offset for CRI |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/174898/#rev3>) | &#91;TEMP&#93; drm/xe/hwmon: use CRI-specific package and VRAM temperature registers |
| `xebr_v7.1.4.46_260728.31` | | | |
| | oot-backport/main | [`1ee3d04e2`](<https://github.com/intel-gpu/xekmd-backports/commit/1ee3d04e2948812eee0a6bfabe3e9a1029028df8>) | drm/xe: Fix CPER tracepoint device-name assignment |
| | oot-backport/main | [`ff8cd3b31`](<https://github.com/intel-gpu/xekmd-backports/commit/ff8cd3b31db42a54e4845a303a695f1253c32f13>) | drm: Backport wedged event support for cold reset |
| | oot-backport/main | [`c06bd6d01`](<https://github.com/intel-gpu/xekmd-backports/commit/c06bd6d015ed39fc8c250de3bb02d53f6a135ef0>) | drm/xe: Add missing cold-reset recovery method |
| |  | Backport-only change | Backport-only: drm/xe/guc: Recommend GuC v70.77.0 for CRI |
| |  | Backport-only change | Backport-only: drm/xe/guc: Recommend GuC v70.77.0 for CRI |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/cper: Add Intel specific CPER structures |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/cper: Emit cper record to trace buf |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/cper: Hardware error CPER reporting from xe_log |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/cper: Log CPER records for aggregate counter retrival |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/cper: Prepare CPER record |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/cper: Prepare Intel CPER error info records |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/cper: Retrieve the error counter record for CPER reporting |
| | linux-next | [`948eee331`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=948eee331bef0c5245bd3c44a6ed99401b8bcca7>) | &#91;TEMP&#93; drm/xe/ras: Validate sysctrl response |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/xe_ras: Add support to retrieve info queue data for CRI |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/xe_ras: Report core compute errors using SIGID |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/xe_ras: Report correctable errors using SIGID |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/xe_ras: Report device memory errors using SIGID |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/169692/#rev3>) | &#91;TEMP&#93; drm/xe/xe_ras: Report soc internal errors using SIGID |
| `xebr_v7.1.4.43_260728.30` | | | |
| | oot-backport/main | [`83367a253`](<https://github.com/intel-gpu/xekmd-backports/commit/83367a2539c4df9e0d1673fe96c316afc89ee9cb>) | backport-include/linux/list_lru: handle unexported list_lru_add |
| | oot-backport/main | [`839d78ffc`](<https://github.com/intel-gpu/xekmd-backports/commit/839d78ffc976c161975aa3fd22e5f6dc8f3a62ba>) | backport-include/linux/list_lru: avoid list_lru_add_obj for TTM |
| `xebr_v7.1.4.43_260728.29` | | | |
| | oot-backport/main | [`f962ae830`](<https://github.com/intel-gpu/xekmd-backports/commit/f962ae83003c68bfe54c552e28f2d1203367b347>) | Mark last_busy in runtime PM autosuspend helpers |
| | oot-backport/main | [`e90944834`](<https://github.com/intel-gpu/xekmd-backports/commit/e9094483450b4a3660e13e70eef84fab081ed7c1>) | Readme: Update Readme with version verification data |
| | ML v6 | [Patchwork](<https://patchwork.freedesktop.org/series/161655/#rev6>) | &#91;TEMP&#93; drm/xe/sysctrl: Add RAS error injection debugfs interface |
| | ML v6 | [Patchwork](<https://patchwork.freedesktop.org/series/161655/#rev6>) | &#91;TEMP&#93; drm/xe/sysctrl: Add generic mailbox passthrough debugfs entry |
| | ML v8 | [Patchwork](<https://patchwork.freedesktop.org/series/164471/#rev8>) | &#91;TEMP&#93; drm/xe/sysctrl: Add helper to check oCode firmware readiness |
| | ML v8 | [Patchwork](<https://patchwork.freedesktop.org/series/164471/#rev8>) | &#91;TEMP&#93; drm/xe/sysctrl: Add helper to query application status |
| | ML v6 | [Patchwork](<https://patchwork.freedesktop.org/series/161655/#rev6>) | &#91;TEMP&#93; drm/xe/sysctrl: Add sysctrl debugfs infrastructure and loopback test interface |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Add DOC text for VSEC |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Add PMT GUID internal access |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Add base_offset to allow for more flexibilty |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Correct locking order |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Crescent Island PMT callbacks |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Crescent Island PMT decode |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Do not register BMG PMT for VF |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Refactor BattleMage PMT defines |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Refactor platform check |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Support Crescent Island PMT |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Support late bind fw information |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Support possible hotplug exit |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Update PMT internal access |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Update VSEC probe order |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; drm/xe/vsec: Use correct pm state get |
| | ML v4 | [Patchwork](<https://patchwork.freedesktop.org/series/162657/#rev4>) | &#91;TEMP&#93; drm/xe/xe_late_bind_fw: Add support to load Ocode firmware |
| | ML v4 | [Patchwork](<https://patchwork.freedesktop.org/series/162657/#rev4>) | &#91;TEMP&#93; drm/xe/xe_late_bind_fw: Convert late bind flag to mask |
| | ML v4 | [Patchwork](<https://patchwork.freedesktop.org/series/162657/#rev4>) | &#91;TEMP&#93; drm/xe/xe_late_bind_fw: Enable late binding support for CRI |
| | ML v4 | [Patchwork](<https://patchwork.freedesktop.org/series/162657/#rev4>) | &#91;TEMP&#93; drm/xe/xe_late_bind_fw: Fix firmware leak on missing manifest entry |
| | ML v4 | [Patchwork](<https://patchwork.freedesktop.org/series/162657/#rev4>) | &#91;TEMP&#93; drm/xe/xe_late_bind_fw: Refactor pm flow |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; platform/x86/intel/pmt: Add register access callbacks |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; platform/x86/intel/pmt: Do not remap when using callbacks |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; platform/x86/intel/pmt: complete pcidev to device update |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; platform/x86/intel/pmt: refactor rc with a return value |
| | ML v12 | [Patchwork](<https://patchwork.freedesktop.org/series/160717/#rev12>) | &#91;TEMP&#93; platform/x86/intel/pmt: refactor rmw with a return value |
| `xebr_v7.1.4.42_260728.28` | | | |
| | oot-backport/main | [`bfe582f26`](<https://github.com/intel-gpu/xekmd-backports/commit/bfe582f2607cd4809e214e14b6038ef7515dbdb9>) | backport-include/linux: Import CXL namespace for AER |
| | oot-backport/main | [`95d5c2197`](<https://github.com/intel-gpu/xekmd-backports/commit/95d5c21975c6a875f4c6ac2178357fcf71c92be5>) | compat: Add pcie_aer_is_native compatibility |
| | ML | [Patchwork](<https://patchwork.freedesktop.org/patch/748149/>) | &#91;TEMP&#93; drm/xe/ras: Enable SGUnit PCIe error reporting |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/749203/?series=173001&rev=1>) | &#91;TEMP&#93; drm/xe/hw_error: Initialize hw_error_work per tile |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/749205/?series=173001&rev=1>) | &#91;TEMP&#93; drm/xe/hw_error: Reuse CSC worker for generic error handling |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/749204/?series=173001&rev=1>) | &#91;TEMP&#93; drm/xe/xe_hw_error: Handle non-fatal errors routed via direct IRQ |
| `xebr_v7.1.4.40_260728.27` | | | |
| | oot-backport/main | [`a9a26b9f9`](<https://github.com/intel-gpu/xekmd-backports/commit/a9a26b9f91372e3aa964921189d39521a6e8e57a>) | backport-include/linux: Backport contiguous buddy allocation in gpu_buddy compat layer |
| | oot-backport/main | [`a62a8155c`](<https://github.com/intel-gpu/xekmd-backports/commit/a62a8155cee78a1c436e7f3a72ddf6d7d614e024>) | backport-include/linux/gpu_buddy: add gpu_buddy_allocated_addr_to_block fallback |
| | oot-backport/main | [`2c3ae7f47`](<https://github.com/intel-gpu/xekmd-backports/commit/2c3ae7f470a37462bff5ec260bf7460a84b9f497>) | patches: fix hunk offsets to resolve hunk failures |
| | xe-next | [`ff796870f`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/ff796870f5ddb0e6040c71b44d3d6247420d216f>) | drm/xe/guc: rework exec queue teardown PM/unplug handling |
| | xe-next | [`b7501c4fd`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/b7501c4fd941a9f8e7c8a4d073658b4a49dcbde9>) | drm/xe: remove EXEC_QUEUE_FLAG_PERMANENT |
| | drm-tip-eudebug | [`aa14a3b4b`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/aa14a3b4bbb073c5fc71ccc79f6400c67cf85473>) | drm/xe: Add EUDEBUG_ENABLE exec queue property |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750693/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Add fault-inject based VRAM page offline injection |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750681/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Export xe_ttm_bo_purge() |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750691/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Expose bad VRAM pages via debugfs |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750684/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Guard teardown paths against purged BOs |
| |  | Backport-only change | drm/xe: Handle NULL resource and allow purging of VRAM pages |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750680/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Link LRC BO and its execution queue with safe lifetime rules |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750679/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Link VRAM resource allocation with gpu buddy |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750683/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Make xe_bo_is_user() public |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750688/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/configfs: Add disable_vram_page_offline attribute |
| |  | Backport-only change | drm/xe/ras: Cache disable_vram_page_offline policy at init |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750692/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/uapi: Expose ban reason in EXEC_QUEUE_GET_PROPERTY_BAN |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750687/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/vram: Add VRAM page offline fault handler |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750686/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/vram: Add page offline data structures and lifecycle |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750690/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/vram: Check disable_vram_page_offline policy in fault handler |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750685/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/vram: Extract buddy alloc and free helpers |
| | xe-next | [`015face96`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/015face96548063e16dfe4dd35ca78355a0f3479>) | drm/xe/multi_queue: Reject PXP usage on multi-queue exec queues |
| | ML v2 | [Patchwork](<https://patchwork.freedesktop.org/series/172733/#rev2>) | &#91;TEMP&#93; drm/xe/xe_ras: Add support for PCIe error component handling |
| | ML v2 | [Patchwork](<https://patchwork.freedesktop.org/series/172733/#rev2>) | &#91;TEMP&#93; drm/xe/xe_ras: Add support for handling Fabric errors |
| | ML v2 | [Patchwork](<https://patchwork.freedesktop.org/series/173403/#rev2>) | &#91;TEMP&#93; drm/xe/cri: Expose device UID through sysfs |
| | ML v2 | [Patchwork](<https://patchwork.freedesktop.org/series/173403/#rev2>) | &#91;TEMP&#93; drm/xe/i2c: Expose AMC Alert reason sysfs |
| |  | Backport-only change | backport_only: Drop force_probe requirement for CRI |
| | xe-next | [`c01743821`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/c01743821d1553b70ae08563b2a36c491b42a07c>) | Revert "drm/xe/guc: Demote uncorrectable local error log to info" |
| | linux-next | [`e199c851c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=e199c851c0ab608a0ca89e7be1756a1461b41a2c>) | drm/xe/gt_throttle: Report power brake as a throttle reason on CRI |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/series/174556/#rev1>) | &#91;TEMP&#93;: drm/pagemap: Drop ratelimiting from dev_unhold_work debug trace |
| `xebr_v7.1.4.31_260728.26` | | | |
| | xe-next | [`a526c0a47`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/a526c0a47517cf2756a3ec9fc721f658be009ce4>) | drm/pagemap: Prevent CPU stalls during unbounded pagemap teardown |
| | xe-next | [`c01743821`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/c01743821d1553b70ae08563b2a36c491b42a07c>) | drm/xe/guc: Demote uncorrectable local error log to info |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/series/154724/#rev3>) | &#91;TEMP&#93; : drm/xe/pf: Keep VF LMEM BAR size low if no VFs enabled |
| `xebr_v7.1.4.29_260728.25` | | | |
| | drm-tip-eudebug | [`8aa56c9b8`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/8aa56c9b878b306357f193a455df31fe06a1acc5>) | drm/xe/eudebug: Don't queue new attention while debugger has unread events |
| `xebr_v7.1.4.28_260728.24` | | | |
| |  | Backport-only change | Backport-only: drm/xe/pm: Temporarily disable D3cold |
| | ML |  | &#91;TEMP&#93; mei: csc: add option for polling and enable it |
| | ML |  | &#91;TEMP&#93; mei: csc: add pci error handling |
| | ML |  | &#91;TEMP&#93; mei: make polling wait interruptible |
| | ML |  | &#91;TEMP&#93; mei: me: avoid hw access in polling when not active |
| | ML |  | &#91;TEMP&#93; mei: me: reduce active polling timeout to 20 ms |
| `xebr_v7.1.4.27_260728.23` | | | |
| |  | Backport-only change | series: Add missing i2c fix |
| |  | Backport-only change | drm/xe/i2c: cancel the client work on remove |
| `xebr_v7.1.4.25_260728.22` | | | |
| | oot-backport/main | [`798e41d10`](<https://github.com/intel-gpu/xekmd-backports/commit/798e41d10156b172b63c7954e0493e5f90c70c30>) | backport/backport-include/linux: Backport from_work macro |
| | oot-backport/main | [`61731e768`](<https://github.com/intel-gpu/xekmd-backports/commit/61731e7689f3afea81568e526705567a58d62ead>) | backport/backport-include/linux: manage FIELD_PREP_CONST availability |
| | oot-backport/main | [`a477ddc75`](<https://github.com/intel-gpu/xekmd-backports/commit/a477ddc75eb21f25a2c11876fe3e1eca775c51b8>) | Add designware_i2c.h file |
| | oot-backport/main | [`b08cf6f77`](<https://github.com/intel-gpu/xekmd-backports/commit/b08cf6f7743d103244875559576e5bd4bf4970e8>) | Revert "TODO:disable xe_i2c compilation based on designware_i2c header" |
| | ML |  | &#91;TEMP&#93; Revert "mei: csc: add option for polling and enable it" |
| | ML |  | &#91;TEMP&#93; Revert "mei: csc: add pci error handling" |
| | ML |  | &#91;TEMP&#93; Revert "mei: make polling wait interruptible" |
| | ML |  | &#91;TEMP&#93; Revert "mei: me: avoid hw access in polling when not active" |
| | ML |  | &#91;TEMP&#93; Revert "mei: me: reduce active polling timeout to 20 ms" |
| `xebr_v7.1.4.24_260728.21` | | | |
| | oot-backport/main | [`98cfe5387`](<https://github.com/intel-gpu/xekmd-backports/commit/98cfe5387f40ec12b3989d75eb2ee308e88f6a4f>) | Enable DKMS rpm package support for drm_ras module |
| `xebr_v7.1.4.24_260728.20` | | | |
| | oot-backport/main | [`9666cb737`](<https://github.com/intel-gpu/xekmd-backports/commit/9666cb737eb87102e0a4be3e1775a35aeb9a0be1>) | drm/drm_ras: parse error counter doit attributes |
| | oot-backport/main | [`6d82ef7e7`](<https://github.com/intel-gpu/xekmd-backports/commit/6d82ef7e7c641b0e1c02a19acde05cd67d12b002>) | drm/drm_ras: register netlink family from module init |
| | oot-backport/main | [`3f4287056`](<https://github.com/intel-gpu/xekmd-backports/commit/3f4287056882e570ce775c90daa499c0f60ab5bf>) | scripts: include DRM RAS module in debian package |
| | oot-backport/main | [`2d6332aa3`](<https://github.com/intel-gpu/xekmd-backports/commit/2d6332aa3b4c4b35a5ecd010a30c71d7a7b160e0>) | drm_ras_genl_family: Add DRM RAS module information |
| | oot-backport/main | [`e1e61d228`](<https://github.com/intel-gpu/xekmd-backports/commit/e1e61d228d7f6aabf1b14ce462fcfa7a60ff6982>) | backport-include/linux: add PCI config dword update helper |
| | oot-backport/main | [`23cfaa12d`](<https://github.com/intel-gpu/xekmd-backports/commit/23cfaa12d9d6f1aa5a94484c13e2e4375ab66054>) | backport-include/drm: add cold reset recovery method |
| | oot-backport/main | [`f0e561633`](<https://github.com/intel-gpu/xekmd-backports/commit/f0e5616331c1a2d8e130dafcb8fb9a111a41d6c3>) | drm/drm_ras_nl: Add DRM RAS split ops support |
| | oot-backport/main | [`91398f1d1`](<https://github.com/intel-gpu/xekmd-backports/commit/91398f1d1c6c414ec734386dd16818d760b82982>) | drm/drm_ras: Add DRM RAS Generic Netlink reply helper |
| | oot-backport/main | [`0a106acd7`](<https://github.com/intel-gpu/xekmd-backports/commit/0a106acd79e8c39be47f8bd497289d08c0655242>) | drm/drm_ras: add DRM RAS dump info helper |
| | oot-backport/main | [`fbb72495c`](<https://github.com/intel-gpu/xekmd-backports/commit/fbb72495c96108511a9b98a9458fe78067cb2e3d>) | backport-include/net: add netlink request attribute helpers |
| | oot-backport/main | [`ba82aecc7`](<https://github.com/intel-gpu/xekmd-backports/commit/ba82aecc75b3fbddc1ce5286d0aa819e8c92f1a3>) | Makefile: Add drm_ras module to build system |
| | oot-backport/main | [`98f62506b`](<https://github.com/intel-gpu/xekmd-backports/commit/98f62506b5bb2d34c4f3109fb6352b007c3e2eba>) | Revert "drm/xe/ras: disable RAS support for older kernel builds" |
| | ML |  | &#91;TEMP&#93; mei: csc: add option for polling and enable it |
| | ML |  | &#91;TEMP&#93; mei: csc: add pci error handling |
| | ML |  | &#91;TEMP&#93; mei: make polling wait interruptible |
| | ML |  | &#91;TEMP&#93; mei: me: avoid hw access in polling when not active |
| | ML |  | &#91;TEMP&#93; mei: me: reduce active polling timeout to 20 ms |
| `xebr_v7.1.4.23_260728.19` | | | |
| | oot-backport/main | [`f9cc1b1e6`](<https://github.com/intel-gpu/xekmd-backports/commit/f9cc1b1e64fb8b37a99a7d814ad679b6d61f4e04>) | scripts: add mei-ccs oot module in rpm and deb packages |
| | oot-backport/main | [`0ae9e26bc`](<https://github.com/intel-gpu/xekmd-backports/commit/0ae9e26bcd1399aead2b8c4a93d2d1489f5e3b3a>) | mei/csc: Add backport compatibility for pcim_iomap_region |
| | oot-backport/main | [`aa42a3029`](<https://github.com/intel-gpu/xekmd-backports/commit/aa42a3029071bbaba223cb935b20c315e4737a3e>) | backport-include/linux/pci: add PCI IRQ flag fallback |
| | oot-backport/main | [`84b8d2214`](<https://github.com/intel-gpu/xekmd-backports/commit/84b8d221488b91d27474b14d05b8e6901ae7de95>) | defconfigs: Enable mei-csc module |
| |  | Backport-only change | series: drm/xe: Add missing entry for PCI error handling fixes |
| | linux-next | [`07fed9b3f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=07fed9b3f47136b6ccc4d71ab283768b6d5daf59>) | drm/xe/gt: Report 'Fault response' pagefault error using SIGID |
| | drm-tip-eudebug | [`ccfe0f20d`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/ccfe0f20da335962ee0516a13e25b61c435c883c>) | drm/xe/eudebug: Enable EU pagefault handling |
| | drm-tip-eudebug | [`df0d510db`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/df0d510db5a08c9d4fd3d8ce5f67ac7d2baecc7c>) | drm/xe/eudebug: Prelim rework for Xe EU debug |
| | xe-next | [`fcc2431d2`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/fcc2431d2213dc4d04250c4f1ae87d9c3ae0d455>) | &#91;BACKPORT-ONLY&#93; drm/xe: Guard page-fault worker with runtime PM check |
| |  | Backport-only change | drm/xe/xe_guc: Skip GuC reset post SBR |
| |  | Backport-only change | drm/xe/xe_pci_error: Wait for pcode init post SBR |
| `xebr_v7.1.4.20_260728.18` | | | |
| | xe-next | [`0cfa716f1`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/0cfa716f19c046b2862eb758200965c5b77b4dce>) | drm/xe/lrc: fix spurious warning when reading context timestamp |
| | xe-next | [`13087ad78`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/13087ad7817e6e5f210064518bfc4d6d58a9c2f3>) | drm/xe: don't WARN on kernel job timeout when device already wedged |
| | xe-next | [`d42df9dce`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/d42df9dce7b374079c5c41691bd62d8765768a80>) | drm/xe: wedge from the timeout handler only after releasing the queue |
| `xebr_v7.1.4.19_260728.17` | | | |
| | oot-backport/main | [`6a447550b`](<https://github.com/intel-gpu/xekmd-backports/commit/6a447550b1c48da62eb719e8a989a717368c5fda>) | drm/xe/Kconfig: select WANT_DEV_COREDUMP for DRM_XE |
| | oot-backport/main | [`3a9dcdcf6`](<https://github.com/intel-gpu/xekmd-backports/commit/3a9dcdcf60f25776f865f271aa361212caaa3894>) | backport/scripts: Add drm_gpuvm module to DKMS configuration |
| `xebr_v7.1.4.19_260728.16` | | | |
| | oot-backport/main | [`33d01ecb4`](<https://github.com/intel-gpu/xekmd-backports/commit/33d01ecb4792ab4debba6d0bd9768b33ace42afa>) | Revert "patches: fix hunk offsets to resolve hunk failures" |
| | oot-backport/main | [`a31f63b00`](<https://github.com/intel-gpu/xekmd-backports/commit/a31f63b00ff4094023c44381bd01525079c89752>) | Revert "backport-include/linux/gpu_buddy: add gpu_buddy_allocated_addr_to_block fallback" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750693/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe: Add fault-inject based VRAM page offline injection" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750691/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe: Expose bad VRAM pages via debugfs" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750682/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe: Extend BO purge to handle vram pages as well" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750684/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe: Guard teardown paths against purged BOs" |
| | ML v10 | [Patchwork](<https://patchwork.freedesktop.org/patch/726250/?series=161473&rev=10>) | &#91;TEMP&#93; Revert "drm/xe: Link LRC BO and its execution Queue" |
| | ML v10 | [Patchwork](<https://patchwork.freedesktop.org/patch/726246/?series=161473&rev=10>) | &#91;TEMP&#93; Revert "drm/xe/kunit: Setup driver data in the test device" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750683/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe: Make xe_bo_is_user public" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750688/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe/configfs: Add bad_page_reservation attribute" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750689/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe/ras: Cache bad_page_reservation policy at init" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750687/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe/vram: Add VRAM page offline fault handler" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750686/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe/vram: Add page offline data structures and lifecycle" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750690/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe/vram: Check bad_page_reservation policy in fault handler" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750685/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe/vram: Extract buddy alloc and free helpers" |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750692/?series=161473&rev=25>) | &#91;TEMP&#93; Revert "drm/xe/uapi: Expose ban reason in EXEC_QUEUE_GET_PROPERTY_BAN" |
| `xebr_v7.1.4.18_260728.15` | | | |
| | oot-backport/main | [`e5334a201`](<https://github.com/intel-gpu/xekmd-backports/commit/e5334a201fa0d7097e0c13abf06b13fa7905968b>) | Fix hunk failures with i2c and Ras changes |
| | oot-backport/main | [`d53dec8dc`](<https://github.com/intel-gpu/xekmd-backports/commit/d53dec8dc8e3b0f4e23a34f9c845dd0c26eb62ba>) | backport-include/linux/gpu_buddy: add gpu_buddy_allocated_addr_to_block fallback |
| | oot-backport/main | [`32b45b593`](<https://github.com/intel-gpu/xekmd-backports/commit/32b45b5935367db1d823eaa11bdfa669c35a8b68>) | patches: fix hunk offsets to resolve hunk failures |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750693/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Add fault-inject based VRAM page offline injection |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750689/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/ras: Cache bad_page_reservation policy at init |
| | linux-next | [`9cc19bb8f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=9cc19bb8f2f6886392b9185b96bbef91b2f1a50f>) | drm/ras: Cancel and free message on get counter failure |
| | linux-next | [`b2207d4c4`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b2207d4c4e84347a3a6b26b77e218cfc606d0109>) | drm/ras: Introduce error threshold |
| | linux-next | [`f3c014033`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f3c0140332fdb8f343a384570f01b879794ddae8>) | drm/xe/drm_ras: Move has_drm_ras check to drm_ras layer |
| | linux-next | [`1b2a3db00`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=1b2a3db0049b4512737abd98d11e4abcc9be079c>) | drm/xe/drm_ras: Wire up error threshold callbacks |
| | linux-next | [`5a2b1a5fb`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5a2b1a5fb42946ad04cdb5fdd764588f2e2e13dd>) | drm/xe/ras: Add support for error threshold |
| | linux-next | [`3799dc5d7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3799dc5d778552e20bc5894d80df54b30fe764c8>) | drm/xe/ras: Fix boot-time ras error processing |
| | linux-next | [`4686fcca6`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=4686fcca694c00fd73eee0f453f32b197baccf9b>) | drm/xe/sysctrl: Reuse xe_sysctrl_create_command() |
| | linux-next | [`f43fa4b85`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f43fa4b8522b>) | drm/xe/i2c: Fix the interrupt handling |
| | linux-next | [`244abef7f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=244abef7f280>) | drm/xe/i2c: Keep the i2c controller always enabled |
| | drm-tip-eudebug | [`e7f9dd9cc`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/e7f9dd9ccc7660babbf1c7654ac183ba2de7d241>) | drm/xe: Debug metadata create/destroy ioctls |
| | drm-tip-eudebug | [`fd2f4b3dc`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/fd2f4b3dcd06ff90cfce7b938f5cb1e0b519a065>) | drm/xe/eudebug: Introduce eudebug support |
| | drm-tip-eudebug | [`df0d510db`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/df0d510db5a08c9d4fd3d8ce5f67ac7d2baecc7c>) | drm/xe/eudebug: Prelim rework for Xe EU debug |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750693/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Add fault-inject based VRAM page offline injection |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750691/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Expose bad VRAM pages via debugfs |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750682/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Extend BO purge to handle vram pages as well |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750684/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Guard teardown paths against purged BOs |
| | ML v10 | [Patchwork](<https://patchwork.freedesktop.org/patch/726250/?series=161473&rev=10>) | &#91;TEMP&#93; drm/xe: Link LRC BO and its execution Queue |
| | ML v10 | [Patchwork](<https://patchwork.freedesktop.org/patch/726246/?series=161473&rev=10>) | &#91;TEMP&#93; drm/xe/kunit: Setup driver data in the test device |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750683/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe: Make xe_bo_is_user public |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750688/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/configfs: Add bad_page_reservation attribute |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750689/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/ras: Cache bad_page_reservation policy at init |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750687/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/vram: Add VRAM page offline fault handler |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750686/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/vram: Add page offline data structures and lifecycle |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750690/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/vram: Check bad_page_reservation policy in fault handler |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750685/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/vram: Extract buddy alloc and free helpers |
| | ML v25 | [Patchwork](<https://patchwork.freedesktop.org/patch/750692/?series=161473&rev=25>) | &#91;TEMP&#93; drm/xe/uapi: Expose ban reason in EXEC_QUEUE_GET_PROPERTY_BAN |
| `xebr_v7.1.4.13_260728.14` | | | |
| | oot-backport/main | [`adb31d4f8`](<https://github.com/intel-gpu/xekmd-backports/commit/adb31d4f8e8be902be8e99bf6e90591cd9887c5a>) | backport/backport-include/linux: Backport disable_delayed_work_sync() api |
| | oot-backport/main | [`6280e9526`](<https://github.com/intel-gpu/xekmd-backports/commit/6280e9526241922670be87d6ffe019120f7030c0>) | drm/xe: Backport pin_vram_percent module parameter |
| | oot-backport/main | [`f7018108c`](<https://github.com/intel-gpu/xekmd-backports/commit/f7018108cc3e4886bce078de270a62421c44d7e4>) | backport-include/linux: resolve dma_resv_for_each_fence_unlocked() api redefinition |
| | oot-backport/main | [`275f78fb2`](<https://github.com/intel-gpu/xekmd-backports/commit/275f78fb2d09135c41406bfcffa93ba854071e48>) | patches: fix hunk offsets to resolve hunk failures |
| | oot-backport/main | [`b5e7310df`](<https://github.com/intel-gpu/xekmd-backports/commit/b5e7310dfe8281af1ce61a126d5f592aea29842e>) | drm/xe: dma-buf Add VRAM pin limit for backports when dmem_cgroup is not present |
| | linux-next | [`6a8789e94`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=6a8789e948c1>) | drm/xe: Add debugfs knob to control GPGPU preemption granularity |
| | ML |  | &#91;TEMP&#93; drm/xe/hwmon: Correct group selection for memory controller temperature |
| | ML |  | &#91;TEMP&#93; drm/xe/hwmon: Detect unavailable temperature sensors |
| | ML |  | &#91;TEMP&#93; drm/xe/hwmon: Use VRAM temperature sensor count from thermal config on CRI |
| | ML |  | &#91;TEMP&#93; drm/xe/vsec: Crescent Island PMT callbacks |
| | ML |  | &#91;TEMP&#93; drm/xe/vsec: Crescent Island PMT decode |
| | ML |  | &#91;TEMP&#93; drm/xe/vsec: Protect against missing config |
| | ML |  | &#91;TEMP&#93; drm/xe/vsec: Support Crescent Island PMT |
| | ML |  | &#91;TEMP&#93; drm/xe/vsec: Support late bind fw information |
| | ML |  | &#91;TEMP&#93; drm/xe/vsec: Support possible hotplug exit |
| | ML |  | &#91;TEMP&#93; drm/xe/vsec: Update PMT internal access for CRI |
| | ML |  | &#91;TEMP&#93; drm/xe/vsec: Use correct pm state get |
| | xe-next | [`adc5d98d9`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/adc5d98d9ff8b5d37e89e11a2ac5512595541329>) | platform/x86/intel/pmc: Add ACPI PWRM telemetry driver for Nova Lake S |
| | xe-next | [`50022e56d`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/50022e56dc89fbf1ec22826edf03dc2e5b9076cc>) | platform/x86/intel/pmc: Add NVL PCI IDs for SSRAM telemetry discovery |
| | xe-next | [`8ba4cf60c`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/8ba4cf60c5ce4a3073126a6cbb09475010f8fa52>) | platform/x86/intel/pmc: Add PMC SSRAM Kconfig description |
| | xe-next | [`08b94937c`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/08b94937c78aaa144e3afff659c6112bffea6bf0>) | platform/x86/intel/pmc/ssram: Add ACPI discovery scaffolding |
| | xe-next | [`d936dd2c6`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/d936dd2c605a17ab41826c1e7f738424d3d0bbfd>) | platform/x86/intel/pmc/ssram: Add PCI platform data |
| | xe-next | [`8a3607ece`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/8a3607ece59fcf84cf4129bdf683cb09122e6b51>) | platform/x86/intel/pmc/ssram: Make PMT registration optional |
| | xe-next | [`f79e57e26`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/f79e57e2677c7641e94d5a38d4b2c2165f5c385c>) | platform/x86/intel/pmc/ssram: Refactor DEVID/PWRMBASE extraction into helper |
| | xe-next | [`90fd47d0d`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/90fd47d0d8109ef1301a60a44a7f85581a1e6efe>) | platform/x86/intel/pmc/ssram: Rename probe and PCI ID table for consistency |
| | xe-next | [`e3c9200a9`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/e3c9200a9c0e05532c495956883ba11fe23a3df0>) | platform/x86/intel/pmc/ssram: Switch to static array with per-index probe state |
| | xe-next | [`acd3b94f8`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/acd3b94f8604aeee2b62f8fd18e95a0474546288>) | platform/x86/intel/pmt: Add pre/post decode hooks around header parsing |
| |  | Backport-only change | platform/x86/intel/pmt: Add register access callbacks |
| | xe-next | [`4dfc7dca6`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/4dfc7dca6e934ca414d8d3c70a84e79d13d9e750>) | platform/x86/intel/pmt: Cache the telemetry discovery header |
| | xe-next | [`4a87492cd`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/4a87492cd137d158779923a034d7e742f7358952>) | platform/x86/intel/pmt: Pass discovery index instead of resource |
| | xe-next | [`13793c7f9`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/13793c7f9e9ff30042a54bb680662b5cfa0f58fa>) | platform/x86/intel/pmt: Unify header fetch and add ACPI source |
| |  | Backport-only change | platform/x86/intel/pmt: complete pcidev to device update |
| | xe-next | [`b3de79d93`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/b3de79d932bdcee4b2b9c8f9a058516699cf1c50>) | platform/x86/intel/pmt/crashlog: Split init into pre-decode |
| | xe-next | [`521460e66`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/521460e6699557f2aa0e4818110e082b76809e98>) | platform/x86/intel/pmt/telemetry: Move overlap check to post-decode hook |
| | linux-next | [`6a8789e94`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=6a8789e948c1>) | drm/xe: Add debugfs knob to control GPGPU preemption granularity |
| | linux-next | [`f0feab6e9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f0feab6e9e00>) | drm/xe: Do not apply WA 14025883347 to media 3503 |
| | linux-next | [`b30c98755`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b30c9875542e>) | drm/xe/hwmon: handle CRI+ power interval encoding |
| | linux-next | [`9b8234d17`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=9b8234d176bb>) | drm/xe/pci_error: Allow debugging PCI errors |
| | linux-next | [`a62212b35`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a62212b35a21>) | drm/xe/sysctrl: Read mailbox phase bit from hardware |
| | linux-next | [`dcf510df4`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=dcf510df4679>) | drm/xe/xe_gt_idle: fix vecs config for powergating info |
| | linux-next | [`53a7115f9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=53a7115f9862>) | drm/xe/xe_ras: Add RAS GPU health indicator |
| | linux-next | [`874ef9a6f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=874ef9a6f2fc>) | i2c: designware: Global register definitions |
| | drm-tip-eudebug | [`3daeea6e4`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/3daeea6e4edcc4771f4fe96cf45c1828070579ba>) | drm/xe/eudebug/xe3p: Pagefault exception debugging support |
| | linux-next | [`3fb4d2c10`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3fb4d2c10702695f33eee9f00a94d2d5e91a5755>) | drm/xe/guc: Update POLICY_SCHED_IF_IDLE documentation |
| | linux-next | [`55d194563`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=55d1945636583f2b88034e50458013f1a9165ee0>) | drm/xe/pf: Allow to change sched_if_idle policy under lock |
| | linux-next | [`0701bf6fc`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0701bf6fce0aa6f0f2122c9a324bd954d3d91b0b>) | drm/xe/pf: Check EQ/PT/PRIO when testing VF config |
| | linux-next | [`689937c71`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=689937c71cbbec927ba2c04f86fd1e59de5097f3>) | drm/xe/pf: Don't reprovision policies if already default |
| | linux-next | [`43533f75c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=43533f75c4577885da1f2e6fddeb88ccf61005f0>) | drm/xe/pf: Encode scheduling priority KLV if needed |
| | linux-next | [`67a5fb1f9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=67a5fb1f9ada7c3d8b7f571be86554968084a4b9>) | drm/xe/pf: Extract helper to show which VFs are provisioned |
| | linux-next | [`4f91e3a5b`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=4f91e3a5b79f3962acff8038dfb89394496faa7d>) | drm/xe/pf: Extract helpers for bulk EQ/PT provisioning |
| | linux-next | [`a43842340`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a438423409692833e3b0f56a1d8440ac1761e594>) | drm/xe/pf: Fix pf_get_sched_priority() function signature |
| | linux-next | [`fbbf73a81`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=fbbf73a81b845ea6fd40688a63570298298d03c1>) | drm/xe/pf: Force new VFs prorities only once |
| | linux-next | [`afc480ff5`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=afc480ff55c5244f3a1941096f232b57c354cc68>) | drm/xe/pf: Perform fair scheduling auto-provisioning |
| | linux-next | [`980bb387f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=980bb387fb08163d0692f25892d8b3e34542349c>) | drm/xe/pf: Print applied policy KLVs |
| | linux-next | [`b23883a08`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b23883a0874fbca9ada07b75509c6126fb5f3575>) | drm/xe/pf: Reprovision policy settings after GT reset |
| | linux-next | [`24ac010a9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=24ac010a97b6e6a65dc32ee2af1cdbe4a44daf7e>) | drm/xe/pf: Reprovision scheduling to default when no VFs |
| `xebr_v7.1.4.11_260728.13` | | | |
| | oot-backport/main | [`058b831b1`](<https://github.com/intel-gpu/xekmd-backports/commit/058b831b1c9a7ccf84b51c0a1c05a72292d73072>) | compat: implement usage-based dma_resv fence tracking backend |
| | oot-backport/main | [`412c38413`](<https://github.com/intel-gpu/xekmd-backports/commit/412c38413005b3f36ee1368040fc0a026c853e5e>) | backport-include: add dma_resv_usage API and teardown recovery hooks |
| `xebr_v7.1.4.11_260728.12` | | | |
| | oot-backport/main | [`7f6ca1d2d`](<https://github.com/intel-gpu/xekmd-backports/commit/7f6ca1d2db66e75415d509aa380f3fc4720a0d05>) | backport/bits: add GENMASK_U16/BIT_U16 and missing helpers |
| | oot-backport/main | [`a43bf1168`](<https://github.com/intel-gpu/xekmd-backports/commit/a43bf1168eb731dc9adf1cf15913527bd502e93c>) | include/drm/drm_prime: Backport drm_gem_dmabuf_mmap() api |
| | linux-next | [`5ebf57fb7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5ebf57fb7c7313c8b621218df67fa420c98346e3>) | drm/xe: Drop unused param from xe_device_create() |
| | linux-next | [`4fb32222c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=4fb32222c0a5ef8d148454c3ee77cab64e65e3ab>) | drm/xe: Introduce xe_any helpers |
| | linux-next | [`5ebf57fb7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5ebf57fb7c7313c8b621218df67fa420c98346e3>) | drm/xe: Move xe-&gt;info.devid&#124;revid initialization |
| | linux-next | [`5ebf57fb7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5ebf57fb7c7313c8b621218df67fa420c98346e3>) | drm/xe: Move xe-&gt;info.force_execlist initialization |
| | linux-next | [`9d91d2c1f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=9d91d2c1f947f7a1fa698f1881248feb602c4b15>) | drm/xe: Report all probe errors using SIGID |
| | linux-next | [`688835ac0`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=688835ac03689556ff32b5b55bbe537c1d15dcc6>) | drm/xe: Report 'device wedged' errors using SIGID |
| | linux-next | [`81a5a4d1c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=81a5a4d1c9aa23d874b5c49cea2c10de4d9c0d43>) | drm/xe: Report 'probe blocked' status using SIGID |
| | linux-next | [`5ebf57fb7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5ebf57fb7c7313c8b621218df67fa420c98346e3>) | drm/xe: Separate early xe_device initialization |
| | linux-next | [`5ebf57fb7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5ebf57fb7c7313c8b621218df67fa420c98346e3>) | drm/xe: Use raw device ID to find sub-platform descriptor |
| | linux-next | [`07fed9b3f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=07fed9b3f47136b6ccc4d71ab283768b6d5daf59>) | drm/xe/gt: Report 'Fault response' pagefault error using SIGID |
| | linux-next | [`968ec2cdc`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=968ec2cdcd6ed4a271932581f27566b29870fa9c>) | drm/xe/gt: Report 'reset failed' errors using SIGID |
| | linux-next | [`9e3536457`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=9e35364579ddd3260e890d90b55a8de597ea00fd>) | drm/xe/guc: Report 'GuC mmio' errors using SIGID |
| | linux-next | [`60fabbdbf`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=60fabbdbf6efe12f4075692d7c732c5536259e6c>) | drm/xe/kunit: Setup driver data in the test device |
| | linux-next | [`23a714120`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=23a71412009828c66690aa674af02f638eb5e39b>) | drm/xe/log: Add SIGID log helpers for component &amp; severity |
| | linux-next | [`a1b89af50`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a1b89af50e0afff03e6055dbd4534d349a27e80b>) | drm/xe/log: Add SIGID log helpers for components |
| | linux-next | [`9dae5c3b0`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=9dae5c3b00f3f5e26e22d18156a1a10d8a783640>) | drm/xe/log: Add SIGID log helpers for errno-only |
| | linux-next | [`eb9316ef7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=eb9316ef7669a1da0940a0982a312f6219dec401>) | drm/xe/log: Add SIGID log helpers for location &amp; severity |
| | linux-next | [`c74b90483`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=c74b9048318a71af3083dda17644aa6897cf3be2>) | drm/xe/log: Add SIGID log helpers for location |
| | linux-next | [`afa3007ca`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=afa3007ca866ca3317493927163e09f993adc41b>) | drm/xe/log: Add SIGID log helpers for severity |
| | linux-next | [`1151b9f6f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=1151b9f6f46570650bdda5931380320119ae97e4>) | drm/xe/log: Add component/location decorations to dmesg |
| | linux-next | [`ceea43a74`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ceea43a746624fb3ec80188918408c8441625247>) | drm/xe/log: Add hardware error signatures |
| | linux-next | [`1d2292f8f`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=1d2292f8f116a6323923352352115931ddefef53>) | drm/xe/log: Add structured SIGID error logging infrastructure |
| | linux-next | [`5fec1a2f4`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5fec1a2f4f7e760acd108a242c24ff620900d3e1>) | drm/xe/log: Extend components list with hardware items |
| | linux-next | [`4d3dd0c94`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=4d3dd0c9464bd342506e075598b3db25c9ee75b3>) | drm/xe/log: Index all SIGID printk messages |
| | linux-next | [`c3bd29281`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=c3bd292810818d8b8e6a01e023f1d5134f8f61ec>) | drm/xe/log: Introduce structured component/location identifiers |
| | linux-next | [`b4f95affc`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b4f95affc66ef76342c1f6bf3849f6c8ade6b9d6>) | drm/xe/pci: Report 'cannot re-enable' error using SIGID |
| | linux-next | [`29fea8370`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=29fea8370983ba0ece7fdcb6fcb1daced5ff3141>) | drm/xe/pcode: Report 'Mailbox failed' error using SIGID |
| | linux-next | [`35241a7a8`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=35241a7a8e57a150944340ec9ccd6de9fb4bb304>) | drm/xe/pcode: Report 'initialization timedout' error using SIGID |
| | linux-next | [`b01fa4815`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b01fa481555e10de9d88addfcc41f527008ff649>) | drm/xe/pcode: Report 'timeout, retrying' error using SIGID |
| | linux-next | [`5ebf57fb7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5ebf57fb7c7313c8b621218df67fa420c98346e3>) | drm/xe/pm: Do early initialization in init_early() |
| | linux-next | [`5ebf57fb7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5ebf57fb7c7313c8b621218df67fa420c98346e3>) | drm/xe/pm: Don't access device in init_early() |
| | linux-next | [`eb732ef76`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=eb732ef76b0ed4fb28194273e21ae620ab600aa9>) | drm/xe/ras: Check RAS and LOG component definitions |
| | linux-next | [`a0e2160a0`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a0e2160a0111e40fc7bd2221cbe2bb6fb4091cff>) | drm/xe/survivability: Report 'Boot Mode enabled' status using SIGID |
| | linux-next | [`f04f7c7aa`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f04f7c7aa651534d723af98c03132c44ffa281c2>) | drm/xe/survivability: Report 'Runtime Mode enabled' status using SIGID |
| | linux-next | [`3cc5107bd`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3cc5107bd611544531799a8c45fe8452d7cc3fc6>) | drm/xe/survivability: Report 'boot status' on sysfs failure |
| | linux-next | [`0e1c4b5de`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0e1c4b5de48135958ec55c22468c2e637eb49f57>) | drm/xe/survivability: Report 'boot status' using SIGID |
| | linux-next | [`33cc29e3d`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=33cc29e3dc0e6530a1eb0a318ff7a414c0c21068>) | drm/xe/survivability: Report sysfs failure in one place |
| | linux-next | [`c352c0bd4`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=c352c0bd4e092a2a005c6810477f54ca502d7f18>) | drm/xe/tests: Add Kunit tests for xe_log |
| | linux-next | [`14cd83cb7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=14cd83cb77d49230edc318a7683fb446259dbfec>) | drm/xe/tests: Add kunit tests for xe_any |
| `xebr_v7.1.4.10_260728.11` | | | |
| |  | Backport-only change | Backport-only:drm/xe/cri: Bump GuC version to 70.70.0 |
| `xebr_v7.1.4.9_260728.10` | | | |
| | oot-backport/main | [`168eb4f3a`](<https://github.com/intel-gpu/xekmd-backports/commit/168eb4f3ab6af6da1b024447802f58bfa49f7183>) | TODO:disable xe_i2c compilation based on designware_i2c header |
| `xebr_v7.1.4.9_260728.9` | | | |
| | oot-backport/main | [`1c676473d`](<https://github.com/intel-gpu/xekmd-backports/commit/1c676473de82f87c80b0835bb5d632af74e731dd>) | backport-include/linux/gpu_buddy: add gpu_buddy_driver_set_lock fallback |
| | oot-backport/main | [`92793b8c2`](<https://github.com/intel-gpu/xekmd-backports/commit/92793b8c2770296dbc31e3ac8b4a73a537ff60a8>) | drm/xe/ras: disable RAS support for older kernel builds |
| | oot-backport/main | [`999cb77ed`](<https://github.com/intel-gpu/xekmd-backports/commit/999cb77ed53b172a89357ff3b0cb3aadb3267f08>) | patches: fix hunk offsets to resolve hunk failures for v7.1.4.9 rebase |
| | linux-next | [`3a4d995cb`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3a4d995cb926da4bd16f9bd4c7104d95105c5eff>) | drm: Add DRM_WEDGE_RECOVERY_COLD_RESET recovery method |
| | linux-next | [`35b535db6`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=35b535db69589ea0025ec3f06df08f2e3faad26f>) | drm/buddy: Integrate lockdep annotations for gpu buddy manager |
| | linux-next | [`048364a21`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=048364a21a4baa6494d3c51d3cf7bccf336d5e35>) | drm/doc: Document DRM_WEDGE_RECOVERY_COLD_RESET recovery method |
| | linux-next | [`6fdbfc75e`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=6fdbfc75eaa1b10ff5d2a45b6b8cf2b57f7a1d03>) | drm/drm_ras: Add drm_ras netlink error event |
| | xe-next | [`151ebbc20`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/151ebbc20aa2365fa854a77432043b16606b5cfe>) | drm/gpu: Add gpu_buddy_allocated_addr_to_block helper |
| | linux-next | [`f543084cd`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f543084cdbd1>) | drm/xe: Add support for WA 16029897822 |
| | linux-next | [`0af278683`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0af278683cd6>) | drm/xe: Add support for WA 22022079272 |
| | linux-next | [`8cd24184c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=8cd24184c0f52f9f4e5a8eafa29ed0078ea33ddd>) | drm/xe: Consolidate debugfs fault injection functions |
| | linux-next | [`9b00f6153`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=9b00f6153614ca495213f1734b63beae844551eb>) | drm/xe: Handle PUNIT errors by requesting cold-reset recovery |
| | linux-next | [`8a1f196b3`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=8a1f196b37bf14c7f8c6793d235e66adeef6c2c5>) | drm/xe: Move xe drm_ras initialization |
| | linux-next | [`e46ee82f1`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=e46ee82f120f7f6ac4a2bf8ee6199ef65ceaea1a>) | drm/xe: Skip device access during PCI error recovery |
| | linux-next | [`caf4fd4eb`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=caf4fd4eb805f227b9bfe7811cc58a9d91a12430>) | drm/xe: add XE_BO_FLAG_NEEDS_1G for minimum page-size sizing |
| | linux-next | [`6bea40fc4`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=6bea40fc4cf3f708c0eac23bdc7e47edc1cc7a8a>) | drm/xe: add page size allocation control state to xe_device |
| | linux-next | [`2285c120e`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=2285c120e1009063d97d15e3d7b18c88356afaec>) | drm/xe: apply debug page-size allocation policy to user BOs |
| | linux-next | [`73c5a2530`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=73c5a253068e8cdf975941a14f032e351730a396>) | drm/xe/configfs: Add enable_multi_queue attribute |
| | linux-next | [`0f800465e`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0f800465ecabac95c434a98681124382bcec6207>) | drm/xe/debugfs: Add debugfs for pcode information |
| | linux-next | [`ceb4e4f0d`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ceb4e4f0df78432128e11dca364207bc7856a339>) | drm/xe/debugfs: add page-size allocation mode knob |
| | linux-next | [`a1e4e62eb`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a1e4e62ebc799ce69236054672253e0086bf409b>) | drm/xe/eustall: Add WA 14027054324 support for graphics IP 35.11 |
| | linux-next | [`4e57574fa`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=4e57574fa3a3>) | drm/xe/guc: Handle GuC local uncorrectable error notifications |
| | linux-next | [`ff33a7f1d`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ff33a7f1d4ea8094ac2b44654737752de6f05a77>) | drm/xe/hw_error: Defeature hardware error handling with system controller |
| | linux-next | [`1c4d0c45d`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=1c4d0c45d762539f174cf1d74b2cb21d18e71363>) | drm/xe/mcr: Take vcs1/vecs1 into account for first media slice |
| | linux-next | [`cffeb4ef6`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=cffeb4ef6f2867df5cc4811b59930dc0fe3ea7e9>) | drm/xe/oa: Extend OAM unit hwe assignment for new dGfx |
| | linux-next | [`f7c05238a`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f7c05238ab72ae72b5f6bd5516b02e7a24fdfd0d>) | drm/xe/pcode: Add support to get pcode version from PMT |
| | linux-next | [`41a74ed31`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=41a74ed31f0bb87035eef9bd4efd92b4e82bcc99>) | drm/xe/pt: allow selecting the bind leaf PTE level |
| | linux-next | [`f29c2bd7e`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f29c2bd7eaeb73afcdbd4e3bbf54d6f8799a9b06>) | drm/xe/ras: Use fault-inject to trigger cold-reset wedge |
| | linux-next | [`60693b580`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=60693b580ab5f7f3158adcc2bab5ae816edd49ff>) | drm/xe/tests: add live KUnit coverage for BO page-size allocation modes |
| | linux-next | [`cdeb5e248`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=cdeb5e248de11537cf23cd5174f6c55bab2e850b>) | drm/xe/uapi: Add additional error components to xe drm_ras |
| | linux-next | [`2f02918ab`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=2f02918ab20397aa5c6b03f46db6bd7024a0ce6a>) | drm/xe/xe_drm_ras: Wire get and clear counter callbacks |
| | linux-next | [`0a0fae332`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0a0fae3327a537b23e86463240e7381ddb5e31a1>) | drm/xe/xe_pci_error: Group all devres to release them on PCIe slot reset |
| | linux-next | [`13b9555ff`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=13b9555ffb0304d736fcad01e7a75d329b81ae9a>) | drm/xe/xe_pci_error: Implement PCI error recovery callbacks |
| | linux-next | [`acc744fa6`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=acc744fa62fb098358f371bfb38e6b32032459c7>) | drm/xe/xe_pci_error: Process errors in mmio_enabled |
| | linux-next | [`63dfab578`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=63dfab5786ca925f6bc90903b7a7b77c99f4708f>) | drm/xe/xe_ras: Add drm_ras feature flag |
| | linux-next | [`25913a062`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=25913a062cd44bc23613b8de56f7261418d88d47>) | drm/xe/xe_ras: Add support for uncorrectable core-compute errors |
| | linux-next | [`2801adbd3`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=2801adbd3449d449431a09dd9382a8ee4f928a2f>) | drm/xe/xe_ras: Add support to clear error counter value |
| | linux-next | [`fe48a8698`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=fe48a86980798ffc78c8713ec964877c8594610d>) | drm/xe/xe_ras: Add support to get error counter value |
| | linux-next | [`942cbdcc8`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=942cbdcc8c07>) | drm/xe/xe_ras: Add support to query device memory errors |
| | linux-next | [`573f9e7ed`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=573f9e7ed1a9>) | drm/xe/xe_ras: Handle uncorrectable SoC Internal errors |
| | linux-next | [`7d8c45885`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=7d8c458854814bf9e9aa4bc217662fd01a86d0f6>) | drm/xe/xe_ras: Initialize Uncorrectable AER Registers |
| | linux-next | [`d9732e498`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d9732e498f5fc1a7e0e3bb287d631c84815a17f7>) | drm/xe/xe_ras: Query errors from system controller on probe |
| | linux-next | [`6a9493e47`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=6a9493e47075>) | drm/xe/xe_ras: Report correctable/uncorrectable error events to userspace |
| | linux-next | [`116932705`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=116932705096281f402ccf779036a814ed89bf56>) | drm/xe/xe_survivability: Decouple survivability info from boot survivability |
| | linux-next | [`f6d8232d0`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f6d8232d0c6978b299237c7c3dd4140c2e9db7ce>) | drm/xe/xe_sysctrl: Make sysctrl flood limit reusable |
| | xe-next | [`3de014f7d`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/3de014f7debc7162ae26db2f6151af1ba5456dc0>) | gpu/tests/gpu_buddy: Add KUnit test for gpu_buddy_allocated_addr_to_block |
| | drm-tip-eudebug | [`a37d1d883`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/a37d1d883359a8482cb27d07ceea6c0eb3edcaee>) | drm/xe: Implement SR-IOV and eudebug exclusivity |
| | drm-tip-eudebug | [`fd2f4b3dc`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/fd2f4b3dcd06ff90cfce7b938f5cb1e0b519a065>) | drm/xe/eudebug: Introduce eudebug support |
| | drm-tip-eudebug | [`e67781291`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/e67781291ae461975057a03d678023f43127b704>) | drm/xe/eudebug: Mark guc contexts as debuggable |
| | drm-tip-eudebug | [`df0d510db`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/df0d510db5a08c9d4fd3d8ce5f67ac7d2baecc7c>) | drm/xe/eudebug: Prelim rework for Xe EU debug |
| | drm-tip-eudebug | [`d9e93b23b`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/d9e93b23b06455b2d037ce090551a729f4ee4265>) | drm/xe/eudebug/xe3p: Per context debugging support |
| | drm-tip-eudebug | [`07100da23`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/07100da23348a6c2a413cd10d471485ccab530dc>) | drm/xe/eudebug_test: Introduce xe_eudebug wa kunit test |
| `xebr_v7.1.4.8_260728.8` | | | |
| | oot-backport/main | [`ef765d26c`](<https://github.com/intel-gpu/xekmd-backports/commit/ef765d26c9dc1f412c3a9e3d14a35a11708a00eb>) | backport-include/linux: Backport dev_pm_smart_suspend() api |
| | oot-backport/main | [`1dd950a73`](<https://github.com/intel-gpu/xekmd-backports/commit/1dd950a738fe022cf1a58a3ce06163e0ba105649>) | drm/xe: Fix backport compatibility for pci_resize_resource() api |
| | oot-backport/main | [`31c6c4283`](<https://github.com/intel-gpu/xekmd-backports/commit/31c6c4283194781591873df7d91609057978948a>) | mei: use non-const class/bus descriptors |
| | oot-backport/main | [`ec07edbe1`](<https://github.com/intel-gpu/xekmd-backports/commit/ec07edbe14f2eacc280a7b1262ed739277c60308>) | mei: bus: fix uevent const argument compatibility |
| | oot-backport/main | [`a79419aca`](<https://github.com/intel-gpu/xekmd-backports/commit/a79419aca2a980a23fdc27b87c9ca3909488df49>) | backport-include/mei: add uuid_le_cmp fallback in mei_uuid.h |
| | oot-backport/main | [`869ae04e8`](<https://github.com/intel-gpu/xekmd-backports/commit/869ae04e85ed2a9a5629da14e24d0aec658cab48>) | mei: handle spi_driver remove/shutdown signature mismatch in vsc-tp |
| | oot-backport/main | [`0dff7ddef`](<https://github.com/intel-gpu/xekmd-backports/commit/0dff7ddefcf2eee739d61512356fa54be9d1e96e>) | backport-include/acpi: add acpi_dev_for_each_child compatibility for mei/vsc-tp |
| | oot-backport/main | [`3c471bbd7`](<https://github.com/intel-gpu/xekmd-backports/commit/3c471bbd743aa498a424f010e2faf01e068ca426>) | mei: remove local uuid_le_cmp from mei_dev |
| | oot-backport/main | [`16d1b95eb`](<https://github.com/intel-gpu/xekmd-backports/commit/16d1b95eb44d2de6d5756b887a76c7cb65b64b23>) | backport-include/drm/display/drm_hdcp: backport drm_hdcp.h file |
| | oot-backport/main | [`9a36c2367`](<https://github.com/intel-gpu/xekmd-backports/commit/9a36c2367febed4b9bcd6762ea349ef988f74e9e>) | mei: add probe-based fallback for linux/mei_uuid.h |
| | oot-backport/main | [`341b89758`](<https://github.com/intel-gpu/xekmd-backports/commit/341b897581e2a9aebb6dad5f6ac338720aa87b42>) | Enable DKMS rpm package support for mei driver |
| | oot-backport/main | [`a5bd25d86`](<https://github.com/intel-gpu/xekmd-backports/commit/a5bd25d86edc4d5eb4223b8b7cb9b54fabf7eca2>) | Enable DKMS deb package support for mei driver |
| | oot-backport/main | [`9f7efdf04`](<https://github.com/intel-gpu/xekmd-backports/commit/9f7efdf049368b48661a2c673a8ad838b6171fe9>) | mei: Use compatible MODULE_IMPORT_NS form for VSC_TP. |
| | oot-backport/main | [`c72361d75`](<https://github.com/intel-gpu/xekmd-backports/commit/c72361d7513e5a69c8330de511a4bcd1d74861d5>) | mei: handle platform remove callback change |
| | oot-backport/main | [`e204f9183`](<https://github.com/intel-gpu/xekmd-backports/commit/e204f9183e6a7a7b5193c50e8dabdcd46b953308>) | mei: add linux/unaligned.h backport header |
| | oot-backport/main | [`070cc64f8`](<https://github.com/intel-gpu/xekmd-backports/commit/070cc64f80f7d258ac414ae716017b4f4633c46c>) | mei: trace: Make code compatible for older assign_str arguments |
| | oot-backport/main | [`794a4b0a4`](<https://github.com/intel-gpu/xekmd-backports/commit/794a4b0a473e20cb3119ed61c6cf11b3a3abcc64>) | mei: bus: fix match callback const argument compatibility |
| | oot-backport/main | [`2131a9e66`](<https://github.com/intel-gpu/xekmd-backports/commit/2131a9e66a09337b3b9f837c4060425081ce98ff>) | Add i915_hdcp_interface.h and i915_pxp_tee_interface.h files |
| | oot-backport/main | [`c29ffa121`](<https://github.com/intel-gpu/xekmd-backports/commit/c29ffa121eacc012478774ab84060ecc7b44771e>) | backport: Enable mei drivers backport support |
| | linux-next | [`35b535db6`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=35b535db69589ea0025ec3f06df08f2e3faad26f>) | Revert "drm/buddy: Integrate lockdep annotations for gpu buddy manager" |
| | xe-next | [`151ebbc20`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/151ebbc20aa2365fa854a77432043b16606b5cfe>) | Revert "drm/gpu: Add gpu_buddy_allocated_addr_to_block helper" |
| | xe-next | [`3de014f7d`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/3de014f7debc7162ae26db2f6151af1ba5456dc0>) | Revert "gpu/tests/gpu_buddy: Add KUnit test for gpu_buddy_allocated_addr_to_block" |
| | linux-next | [`35b535db6`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=35b535db69589ea0025ec3f06df08f2e3faad26f>) | drm/buddy: Integrate lockdep annotations for gpu buddy manager |
| | xe-next | [`151ebbc20`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/151ebbc20aa2365fa854a77432043b16606b5cfe>) | drm/gpu: Add gpu_buddy_allocated_addr_to_block helper |
| | xe-next | [`3de014f7d`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/3de014f7debc7162ae26db2f6151af1ba5456dc0>) | gpu/tests/gpu_buddy: Add KUnit test for gpu_buddy_allocated_addr_to_block |
| `xebr_v7.1.4.6_260728.7` | | | |
| | linux-next | [`a196406a3`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a196406a3831291598fe8e73245914f7acffdfe0>) | drm/xe: Fix DPT allocation paths. |
| | linux-next | [`a2c2d2b13`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a2c2d2b13a9ea9494d2d76b46273833111749507>) | drm/xe: Fix a bug in pc_adjust_freq_bounds() |
| | linux-next | [`f6b6cc111`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f6b6cc1118bdbc4265fa8b3bdf8565b26f13e56e>) | drm/xe: Fix memory leak in exec_queue_set_hang_replay_state() |
| | linux-next | [`5ce3042c6`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5ce3042c67c539480882567137ff8d56118885d6>) | drm/xe: Fix xe_device_probe() failure |
| | linux-next | [`136360290`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=136360290f314890428a3fbf31aaa8e4f1d43567>) | drm/xe: Order ring writes before ring tail updates |
| | linux-next | [`ace076ef0`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ace076ef0a854ab5940bacc539bf66afd61d118c>) | drm/xe/guc_ads: allocate UM queues in VRAM on dGFX |
| | linux-next | [`6af05de0d`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=6af05de0dc19bbf3aaeec2020fe48b37c834b811>) | drm/xe/guc_ads: allocate UM queues in a separate BO |
| | linux-next | [`9daa302a8`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=9daa302a82590eeee7bdc68023ddad302df4b88c>) | drm/xe/guc_ads: use uncached mapping for UM queue BO |
| | linux-next | [`360b293de`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=360b293de27bfdd0d07047f8efd5ba8e91fa90b7>) | drm/xe/oa: Check managed mutex initialization errors |
| | linux-next | [`8af97b3da`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=8af97b3da2cfce04e6b457c6eb17ed3c1daf912b>) | drm/xe/oa: Fix sync entry leak on OA config emit failure |
| | linux-next | [`757bda2b8`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=757bda2b8b93fa36ad9b2c7993081d5f9d0d6e3b>) | drm/xe/pxp: add termination on resume |
| | linux-next | [`28a4198c5`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=28a4198c52a1468fc1b620a9837557ea1dc1766d>) | drm/xe: tests: fix error message in xe_migrate_sanity_test() |
| | linux-next | [`f09360e85`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f09360e857130f7ab7f069e2421e6b4a6e502531>) | drm/xe/uc: Apply RCS/CCS yield policy to SR-IOV VFs |
| | linux-next | [`3359422bf`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3359422bf0a1140e96d783a19a397686e580a3ca>) | drm/xe/userptr: Stub notifier_lock helpers when DRM_GPUSVM=n |
| `xebr_v7.1.4.5_260728.6` | | | |
| | oot-backport/main | [`3f60d3edf`](<https://github.com/intel-gpu/xekmd-backports/commit/3f60d3edf036371876cfe3d9723b751923b900da>) | migrate.h: fix enum compatibility guards for migrate selection flags |
| | oot-backport/main | [`cf8631d77`](<https://github.com/intel-gpu/xekmd-backports/commit/cf8631d770a334ddced002bce8f544a475ec6b05>) | migrate.h: split migrate_device API gating |
| | oot-backport/main | [`72e03ec6d`](<https://github.com/intel-gpu/xekmd-backports/commit/72e03ec6d03c92616de7bfd15516bb9303bdaa10>) | memremap.h: fix zone_device_page_init() gating for 1-arg kernels |
| `xebr_v7.1.4.5_260728.5` | | | |
| | oot-backport/main | [`6cea1f5ad`](<https://github.com/intel-gpu/xekmd-backports/commit/6cea1f5adfc808a49fa4c52a277d663e73c17af1>) | fixup! drm/ttm: Fix NULL pointer dereference in ttm_bo_vm_fault_reserved |
| | linux-next | [`a6b842acf`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a6b842acf3ddd1efc53a56de9260cfa718fb35e7>) | drm/xe: Wait on external BO kernel fences in exec IOCTL |
| | linux-next | [`da1124aba`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=da1124abac689cc2b1d8995e5f0a816f8a122edb>) | drm/xe/guc: Hold device ref until queue teardown completes |
| | linux-next | [`41075f0eb`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=41075f0eb5dcbd3b065d15f15ef7bbe9315188e8>) | drm/xe/guc: Keep scheduler timeline name alive |
| | linux-next | [`a79f6abc8`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a79f6abc8b516b5bd906e2eca8121e3549ee163f>) | drm/xe/i2c: Allow per domain unique id |
| | linux-next | [`04eeeb45c`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=04eeeb45cb61b8a3e9d785003457e550c920ba49>) | drm/xe/pt: check no-DMA huge-pte cases before DMA segment test |
| | linux-next | [`61596826b`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=61596826b89af9dc20a53bae79b2b41e2bdc1fb5>) | drm/xe/rtp: Fix build error with clang &lt; 21 and non-const initializers |
| | linux-next | [`ca2a3587d`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ca2a3587d577ba764e0fe628fb676244fc33ddd4>) | drm/xe/vm: Fix SVM leak on resv obj alloc failure in xe_vm_create() |
| `xebr_v7.1.4.4_260728.4` | | | |
| |  | Backport-only change | xe/prelim/eudebug: Avoid taking discovery lock on teardown |
| `xebr_v7.1.4.3_260728.3` | | | |
| | oot-backport/main | [`1ee1b005e`](<https://github.com/intel-gpu/xekmd-backports/commit/1ee1b005e43e13fc55157e1a179c0be56a34fee3>) | list_lru: use caller nid in list_lru_add() shim |
| `xebr_v7.1.4.3_260728.2` | | | |
| | oot-backport/main | [`00a3d828e`](<https://github.com/intel-gpu/xekmd-backports/commit/00a3d828e45fb47844609b5e53465f38be8f3882>) | Readme: Align Xe Name in doc |
| `xebr_v7.1.4.3_260728.1` | | | |
| | oot-backport/main | [`f46813fdd`](<https://github.com/intel-gpu/xekmd-backports/commit/f46813fdd08c48b1bb6f7d276ef391472e0f0ff5>) | patches: fix hunk offsets to resolve hunk failures for v7.1.4 rebase |
| | oot-backport/main | [`2abb7564e`](<https://github.com/intel-gpu/xekmd-backports/commit/2abb7564e52fc11abcadef5eff23431c8d619fb1>) | backport-include/kobject: fix const kobj_type warnings |
| | drm-tip-eudebug | [`e7a445611`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/e7a445611c14cfc87da2ae57ba5a045711433253>) | fixup! drm/xe/eudebug: Introduce EU control interface |
| | drm-tip-eudebug | [`706aeb868`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/706aeb86823c6c3208cafe35bdc62ca7d28b7058>) | fixup! drm/xe/eudebug: Introduce EU pagefault handling interface |
| | drm-tip-eudebug | [`0844542b5`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/0844542b5018635d244998c398e94bbe98ecd967>) | fixup! drm/xe/eudebug: Introduce per device attention scan worker |
| | linux-next | [`959b5016e`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=959b5016e4646b55fd2fd0438932e4c4e9ce171f>) | Remove "drm/xe/oa: Fix offset alignment for MERT WHITELIST_OA_MERT_MMIO_TRG" |
| | drm-tip-eudebug | [`ecab48471`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/ecab484710fbd81e99736988fcc4fd35d9b3f8f8>) | drm/xe/eudebug: Dynamically toggle debugger functionality |
| | drm-tip-eudebug | [`7305cacd6`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/7305cacd6b2936b48b9fbffdfbc65b283e7d8b75>) | drm/xe/eudebug: hw enablement for eudebug |
| | drm-tip-eudebug | [`f922a77a2`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/f922a77a2c00ff4336ff887d5f167930aad0fdb1>) | drm/xe/xe3p: disable EU thread hang on exception |
| | linux-next | [`ba7fd1634`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ba7fd163422877ad5a5cf31306a38c07d3932b0c>) | drm/xe: Set TTM device beneficial_order to 9 (2M) |
| | linux-next | [`d47249726`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d472497265374e895e31cf2af8a2c5f650019889>) | drm/xe/display: skip FORCE_WC and vm_bound check for external dma-bufs |
| | linux-next | [`63ddb3ad0`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=63ddb3ad08ff4e89c108499dfec5e9be5ddc25c9>) | drm/xe/oa: (De-)whitelist OA registers on OA stream open/release |
| | linux-next | [`e23fafb85`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=e23fafb8594ea886ee03e005cc32dfda24f417cf>) | drm/xe/rtp: Add struct types for RTP tables |
| | linux-next | [`ebba7ce65`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ebba7ce65252a4ab0e3794ff14854df2afca5c08>) | drm/xe/rtp: (De-)whitelist OA registers for all hwe's for a gt |
| | linux-next | [`ef78e2a22`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ef78e2a22f72c892fd6663f0760abd208d49a3e2>) | drm/xe/rtp: Ensure locking/ref counting for OA whitelists |
| | linux-next | [`4fe2844b0`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=4fe2844b0f0c7cdc45ca4c4c62ca56b7f26c514c>) | drm/xe/rtp: Generalize whitelist_apply_to_hwe |
| | linux-next | [`60d49ea28`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=60d49ea28bb190a640bd8dc3f4c946e0811a948c>) | drm/xe/rtp: Keep track of non-OA nonpriv slots |
| | linux-next | [`31e243756`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=31e2437561621b4867c08efc890bf629d017df03>) | drm/xe/rtp: Maintain OA whitelists separately |
| | linux-next | [`a19a83721`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a19a83721a28ccaddace846da70da5c53d7dd052>) | drm/xe/rtp: Save OA nonpriv registers to register save/restore lists |
| | xe-next | [`b422babd7`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/b422babd77fac2c96b92db484050e460899bddaf>) | drm/xe/rtp: Toggle 'deny' bit to (de-)whitelist OA regs |
| | linux-next | [`0b5ed2756`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0b5ed2756d45b04669502a1f13b1657ec7664571>) | drm/xe: Add compact-PT and addr mask handling for page reclaim |
| | linux-next | [`e6f2d0b75`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=e6f2d0b757c4fb577a513c577140109d1d292a9a>) | drm/xe: Fix PTE index in xe_vm_populate_pgtable() for chunked binds |
| | linux-next | [`92dc59ab2`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=92dc59ab2a09097cdf249e0288ff9b69261761c6>) | drm/xe: Fix wa_oob codegen recipe for external module builds |
| | linux-next | [`3516f3fae`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3516f3fae6be35642f8f06f8a218da6425c0306a>) | drm/xe: Hold a dma-buf reference for imported BOs |
| | linux-next | [`136fb61ba`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=136fb61ba8571076dc5d49350a0e6d002d740b74>) | drm/xe: Return error on non-migratable faults requiring devmem |
| | linux-next | [`b5c55015d`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b5c55015d4164a0f206bcdcf2985da948b3c7837>) | drm/xe: fix NPD in bo_meminfo() |
| | linux-next | [`c3a1c3579`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=c3a1c3579b1250060da73507a4acef712974c78a>) | drm/xe: free madvise VMA array on L2 flush failure |
| | linux-next | [`632ecc90e`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=632ecc90e1ca5d3b6822bb4d08f84a175b6c42c0>) | drm/xe/guc: Fix buffer overflow in steered register list allocation |
| | linux-next | [`7ac3cae7a`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=7ac3cae7a251d28e9079de07a991bd4eb2bb7fd8>) | drm/xe/hw_engine: Fix double-free of managed BO in error path |
| | linux-next | [`2007be18d`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=2007be18d2318a59748da5da1b8968042213d5f1>) | drm/xe/nvm: fix writable override for CRI |
| | linux-next | [`959b5016e`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=959b5016e4646b55fd2fd0438932e4c4e9ce171f>) | drm/xe/oa: Fix offset alignment for MERT WHITELIST_OA_MERT_MMIO_TRG |
| | linux-next | [`ed8b0d731`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ed8b0d731892c68b41ecbd27c952af284816dec1>) | drm/xe/pf: Don't attempt to process FAST_REQ or EVENT relays |
| | linux-next | [`3feeb6671`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3feeb667197bd58a17f4edfdbcad249ffcb3c864>) | drm/xe/pt: Fix NULL pointer dereference in xe_pt_zap_ptes_entry() |
| | linux-next | [`046045543`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=046045543e530605c441063535e7dca0075369a6>) | drm/xe/pt: Reset current_op in xe_pt_update_ops_init() |
| | linux-next | [`8a0fb5767`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=8a0fb57675be578c4db19deb4298ed08a70f0f1a>) | drm/xe/pt: prevent invalid cursor access for purged BOs |
| | linux-next | [`84ed5b0a9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=84ed5b0a925721aaf069d36e18a99db966ff4e80>) | drm/xe: remove duplicate &lt;kunit/test-bug.h&gt; include |
| | linux-next | [`e70086a3a`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=e70086a3a06d276b4a5d9a2c51c9330c6cf72780>) | drm/xe/rtp: Add RING_FORCE_TO_NONPRIV_DENY to OA whitelists |
| | linux-next | [`0c56ea482`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=0c56ea482aab1470b96a525ef53fa3eb8704f9a6>) | drm/xe/userptr: Drop bogus static from finish in force_invalidate |
| | linux-next | [`dca6e08c9`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=dca6e08c923a44d2d66b955e03dd57a3a38c2b94>) | drm/xe/userptr: Hold notifier_lock for write on inject test path |
| | linux-next | [`1ae415a6e`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=1ae415a6eefe5004954a1d352b1718faca8844ef>) | drm/xe/vf: Add drm_dev guards when detaching CCS read/write buffers |
| | linux-next | [`d45ad0aa7`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d45ad0aa7a1eb5d7288b5ed948b05695611dc39e>) | drm/xe/vf: Fix VF CCS attach/detach race with in-flight BO moves |
| | linux-next | [`d9a4906ac`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d9a4906ac03be9f6ed3f3b45c56c866b867fd75b>) | drm/xe/vm: Fix BO prefetch with CONSULT_MEM_ADVISE_PREF_LOC |
| | linux-next | [`3033b0b24`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=3033b0b24ed0e2f5e56bdd4d9c183417c365a45b>) | drm/xe/wopcm: fix WOPCM size for LNL+ |
| `xebr_v7.1.4.0_260728.0` | | | |
| |  | Backport-only change | config: Rebase to v7.1.4 |
| | xe-next | [`959b5016e`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/959b5016e4646b55fd2fd0438932e4c4e9ce171f>) | drm/xe/oa: Fix offset alignment for MERT WHITELIST_OA_MERT_MMIO_TRG |
| | xe-next | [`375bbbbd1`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/375bbbbd112af028ee0b45d833a6233c23d19bbf>) | platform/x86/intel/vsec: Restore BAR fallback for header walk |
| `xebr_v7.1.1.3_260722.1` | | | |
| | oot-backport/main | [`d286f664f`](<https://github.com/intel-gpu/xekmd-backports/commit/d286f664f855583385289fef9efa39a06f2221e8>) | pgtable/huge_mm: fix PMD_ORDER/vmf_insert_pfn issues on 5.15 LTS |
| | oot-backport/main | [`5e8492608`](<https://github.com/intel-gpu/xekmd-backports/commit/5e849260837aaad0325beed69cfb3c03be96f143>) | cleanup.h: restore HAVE_LINUX_CLEANUP_H and scoped_cond_guard fallbacks |
| | oot-backport/main | [`a582cbc56`](<https://github.com/intel-gpu/xekmd-backports/commit/a582cbc56c9ef3345fdf35a636fd1af897114500>) | vfio/xe: keep get_region_info_caps when building the full VFIO framework |
| | oot-backport/main | [`17099a7a5`](<https://github.com/intel-gpu/xekmd-backports/commit/17099a7a58edeb221b7390fcd7b53240b51ec1d3>) | vfio/iommu: fix isolated-MSI detection for VFIO |
| | oot-backport/main | [`35311a12b`](<https://github.com/intel-gpu/xekmd-backports/commit/35311a12b585127fa08998af8e8e3644bc5265fa>) | Fix vfio const class register write fault on pre-const kernels |
| | oot-backport/main | [`cee48b74c`](<https://github.com/intel-gpu/xekmd-backports/commit/cee48b74cfe6164b1e37b9c9a35940931aa0c774>) | drm/xe: use gpu_buddy_block_trim() for the CONTIGUOUS fallback |
| | oot-backport/main | [`8d0b644a1`](<https://github.com/intel-gpu/xekmd-backports/commit/8d0b644a189e07d063c1dac32deb319068bee6b1>) | Fix class-&gt;devnode prototype mismatch in vfio_main.c |
| | oot-backport/main | [`3ef97c162`](<https://github.com/intel-gpu/xekmd-backports/commit/3ef97c16243283ab6e8e8eb18f74663f3e67d2bd>) | compat: Backport device_set_driver_override() api |
| | oot-backport/main | [`5b97fdeb8`](<https://github.com/intel-gpu/xekmd-backports/commit/5b97fdeb89b86bd42c2274592908da00253aca61>) | vfio/pci: forward declare struct phys_vec in vfio_pci_core.h |
| | oot-backport/main | [`5631409e4`](<https://github.com/intel-gpu/xekmd-backports/commit/5631409e45ee000ecd18ff65a5915d169cc09c2a>) | Pull in string_choices.h from linux/string.h wrapper |
| | oot-backport/main | [`17fe7eb9b`](<https://github.com/intel-gpu/xekmd-backports/commit/17fe7eb9b4928d04087012981ca30a8dd4eceee6>) | backport-include/memremap: Use struct page instead of struct folio |
| | oot-backport/main | [`b10d274fe`](<https://github.com/intel-gpu/xekmd-backports/commit/b10d274fe9569d0fd98d731512fc46dc07cf8143>) | Control migrate_vma_* helpers on CONFIG_DEVICE_PRIVATE |
| | oot-backport/main | [`640a24df4`](<https://github.com/intel-gpu/xekmd-backports/commit/640a24df497a9650201f8ae4ce66b6d2a0002088>) | migrate.h: add migrate.h compat for device migration APIs |
| | oot-backport/main | [`80d684385`](<https://github.com/intel-gpu/xekmd-backports/commit/80d684385fc644328cd1a6b7bf03fecfacb28e06>) | Makefile: suppress -Wdeclaration-after-statement for backported drivers |
| | oot-backport/main | [`146ef4970`](<https://github.com/intel-gpu/xekmd-backports/commit/146ef497009f43d077e1baed5ef89127ec2525c5>) | Add shrinker.h compat for register_shrinker() arg count |
| | oot-backport/main | [`bb00e82cc`](<https://github.com/intel-gpu/xekmd-backports/commit/bb00e82cc15a33332a95a2c3229f05ac18fba6ea>) | memremap.h: add memremap.h compat for zone_device_page_init |
| | oot-backport/main | [`55c4ec5ac`](<https://github.com/intel-gpu/xekmd-backports/commit/55c4ec5ac8a6cf24ac9efe1b40ff03a4a431e543>) | drm/pagemap: guard migrate_vma fault_page initializer on older kernels |
| | oot-backport/main | [`01127c4d1`](<https://github.com/intel-gpu/xekmd-backports/commit/01127c4d1419484b21faf34e2997766e7ca9f31c>) | compat: Backport parse_int_array_user() compat |
| | oot-backport/main | [`6c850a017`](<https://github.com/intel-gpu/xekmd-backports/commit/6c850a017b2f9e83b6ef7819cfcf7714ac386d75>) | panic.h: add TAINT_TEST macro |
| | oot-backport/main | [`c1e4e1ea6`](<https://github.com/intel-gpu/xekmd-backports/commit/c1e4e1ea6fa2480f017ebc5c750dde17ded3fa4c>) | mm.h: Add device-coherent page and folio API compatibility |
| | oot-backport/main | [`2b53febb8`](<https://github.com/intel-gpu/xekmd-backports/commit/2b53febb83119b37f585971e2380eda353a3e211>) | backport-include/mm.h: Add num_pages_contiguous helper function |
| | oot-backport/main | [`810f10d33`](<https://github.com/intel-gpu/xekmd-backports/commit/810f10d33e5e264385a4a9c1d70780fccda2cb76>) | overflow.h: Add range_overflows() and struct_size_t() compatibility |
| | oot-backport/main | [`70476ea62`](<https://github.com/intel-gpu/xekmd-backports/commit/70476ea6224cbc69c842e40d73fea4b2c4e25bca>) | Add FD_ADD() macro compatibility |
| | oot-backport/main | [`ccd107d8b`](<https://github.com/intel-gpu/xekmd-backports/commit/ccd107d8b91fb074f88444e558c6d1d4b3ef769e>) | Disable VFIO_PCI_DMABUF where its dependencies are absent |
| | oot-backport/main | [`649681de7`](<https://github.com/intel-gpu/xekmd-backports/commit/649681de7ddc59d07efd8b6d4ea9d717e1a93460>) | Resolve the error and warnings for ubuntu_26.04 support |
| `xebr_v7.1.1.3_260722.0` | | | |
| | oot-backport/main | [`3d66b2100`](<https://github.com/intel-gpu/xekmd-backports/commit/3d66b210095625eef110dfd3d0441eab32e1cba4>) | drm/xe: fix NULL pointer dereference in devcoredump capture path |
| | oot-backport/main | [`c434875f1`](<https://github.com/intel-gpu/xekmd-backports/commit/c434875f16825783caad3f2fd4e7e546ab368a65>) | backport/include/drm: copy gpu_buddy core sources for split drm_buddy allocator |
| | oot-backport/main | [`1f6f44402`](<https://github.com/intel-gpu/xekmd-backports/commit/1f6f44402960bb4c634e5a260b79035109a75ff8>) | patches: cleanup alignment fix and remove obsolete patch |
| | oot-backport/main | [`008d43d88`](<https://github.com/intel-gpu/xekmd-backports/commit/008d43d88172b047d43cb10f523c7ca8126ed6a0>) | drm/pagemap: handle folio_split member unavailability |
| | oot-backport/main | [`f74e00411`](<https://github.com/intel-gpu/xekmd-backports/commit/f74e00411dba3111b9692e89f0ef72995be379ed>) | mm/migrate_device: disable THP migration if not supported |
| | oot-backport/main | [`695eab385`](<https://github.com/intel-gpu/xekmd-backports/commit/695eab38545428cf14df6c0c60ae3a6e589eb72e>) | drm/pagemap: Use zone_device_page_init() for zone device memory initialization |
| | oot-backport/main | [`3efffc161`](<https://github.com/intel-gpu/xekmd-backports/commit/3efffc16100c095934e35fafd1483dce33f58df7>) | drm/xe: use single-pass MMU notifier when invalidate_start/finish not present |
| | oot-backport/main | [`54c993c10`](<https://github.com/intel-gpu/xekmd-backports/commit/54c993c10e1b0ad667143004f748e4f7dab12917>) | backport-include/drm/drm_suballoc: backport drm_suballoc helper functions |
| | oot-backport/main | [`5a7529904`](<https://github.com/intel-gpu/xekmd-backports/commit/5a7529904eb11f71817db3d15a2af020a2c4412b>) | backport-include/linux/memremap: backport folio_zone_device_data() |
| | oot-backport/main | [`6cc42dc52`](<https://github.com/intel-gpu/xekmd-backports/commit/6cc42dc52591f1dd0b6f6bacbee6229428b03479>) | copy-list: include new drm/xe headers required for 7.1KV backport |
| | oot-backport/main | [`6c037bd71`](<https://github.com/intel-gpu/xekmd-backports/commit/6c037bd711161747305f7fe35d4f080e40aa79e6>) | drm/xe: Handle DRM_BUDDY_CONTIGUOUS_ALLOCATION flag with fallback for older kernels |
| | oot-backport/main | [`37b6d756e`](<https://github.com/intel-gpu/xekmd-backports/commit/37b6d756ecce26889123fc73aa4028e8d2ad1b0b>) | backport-include/gpu_buddy: rename gpu_buddy to drm_buddy |
| | oot-backport/main | [`f2ced94fa`](<https://github.com/intel-gpu/xekmd-backports/commit/f2ced94fa5dd413656022115d74a3341cedcec41>) | backport-include/linux/workqueue: add WQ_PERCPU stub |
| | oot-backport/main | [`cc376f7ba`](<https://github.com/intel-gpu/xekmd-backports/commit/cc376f7ba9d082b075432d3810e7169ef8719bd8>) | backport-include/linux/workqueue: provide fallback for system_dfl_wq() unavailability |
| | oot-backport/main | [`1f64d5c3a`](<https://github.com/intel-gpu/xekmd-backports/commit/1f64d5c3a67fa5cee31a5fbd09ef2b2a2d79a1b1>) | drm/ttm: stop updating nr_gpu_reclaim/active sys entries for gpu memory tracking |
| | oot-backport/main | [`fa1705f3a`](<https://github.com/intel-gpu/xekmd-backports/commit/fa1705f3afd3e9390d0544146b29d0621390c2e2>) | drm/ttm: provide fallaback implementation for take_one_from_lru() and pool_move_to_dispose_list() |
| | oot-backport/main | [`d4f57dc42`](<https://github.com/intel-gpu/xekmd-backports/commit/d4f57dc4242d727754ae076f93a984417f1d5d44>) | backport-include/linux/list_lru: provide backport compatability for list_lru_add_obj() |
| | oot-backport/main | [`d776a3676`](<https://github.com/intel-gpu/xekmd-backports/commit/d776a3676a2ba9a058fa10464f2461a183a30a02>) | backport-include/linux/list_lru: backport list_lru_add() |
| | oot-backport/main | [`184b3ac5e`](<https://github.com/intel-gpu/xekmd-backports/commit/184b3ac5e1479019409f15802eb3f2f20345e3dc>) | backport-include/linux/dma-fence: backport for dma_fence_lock_irqsave and restore() |
| | oot-backport/main | [`3e5d414d8`](<https://github.com/intel-gpu/xekmd-backports/commit/3e5d414d89f5f3c8d36647e2b49408ea830451d2>) | backport-include/linux/dma-fence: handle the map from extern_lock to lock |
| | oot-backport/main | [`58c5bfc20`](<https://github.com/intel-gpu/xekmd-backports/commit/58c5bfc20f539c7a33871b8f1138d13161586e49>) | backport-include/linux/dma-buf: provide flag handling for .invalidate_mappings() |
| | oot-backport/main | [`214c63777`](<https://github.com/intel-gpu/xekmd-backports/commit/214c637779023f437e61f49191a0f0b23f744356>) | backport-include/dma-buf: backport dma_buf_invalidate_mappings() |
| | oot-backport/main | [`a1bde525e`](<https://github.com/intel-gpu/xekmd-backports/commit/a1bde525ed90dfda59b6674ddccdaae47a3ebc79>) | compat/bitmap: backport missing export symbol  __bitmap_weighted_or() |
| | oot-backport/main | [`4271ae536`](<https://github.com/intel-gpu/xekmd-backports/commit/4271ae5363d1b55303febaf66d623936f7198f23>) | backport-include/bitmap: backport bitmap_weighted_or() |
| | oot-backport/main | [`757be1a69`](<https://github.com/intel-gpu/xekmd-backports/commit/757be1a69ad44f7b172769b190e221fc031fe32d>) | patches: fix hunk offsets to resolve hunk failures |
| | oot-backport/main | [`bc79b79ef`](<https://github.com/intel-gpu/xekmd-backports/commit/bc79b79efcb02f31b8add0dde5e8f27a8100afe8>) | patches: cleanup alignment fix and remove obsolete patch |
| | oot-backport/main | [`4ddd7c1bb`](<https://github.com/intel-gpu/xekmd-backports/commit/4ddd7c1bb788f424e5200516407a4e5cc83fde5f>) | patches: align xe makefile and userptr runtime compatibility |
| | oot-backport/main | [`dc9f5a621`](<https://github.com/intel-gpu/xekmd-backports/commit/dc9f5a621f8311708187ed327f074c1206932426>) | drm/gpuvm: add sm_map_ops_create() signature compatibility |
| | oot-backport/main | [`9a64b8992`](<https://github.com/intel-gpu/xekmd-backports/commit/9a64b8992e03ab30fbe2cc50c776bfdf90e8a060>) | patches: gate Xe full-SVM paths on backport capability checks |
| | oot-backport/main | [`2bbb9b767`](<https://github.com/intel-gpu/xekmd-backports/commit/2bbb9b767c97301d366f68bd37dcf5c1c21a4002>) | patches: add drm_pagemap_put compat guard for older kernels |
| | oot-backport/main | [`ea9f732ec`](<https://github.com/intel-gpu/xekmd-backports/commit/ea9f732ece94798776d5e5fcb97525a465ea6ac3>) | backport: fix dkms module indexing for gpuvm and gpusvm helper |
| | oot-backport/main | [`34de2dc97`](<https://github.com/intel-gpu/xekmd-backports/commit/34de2dc97c4504b5b2689a54353a117131babfd6>) | drm: Add drm_gem_gpuva struct compatibility for lockdep_map |
| | oot-backport/main | [`f7217fe7a`](<https://github.com/intel-gpu/xekmd-backports/commit/f7217fe7ae24ca314a7ff3c92873d8325d711ae8>) | patches: restore submit_wq assignment in guc_exec_queue_init compat path |
| | oot-backport/main | [`052f53ec1`](<https://github.com/intel-gpu/xekmd-backports/commit/052f53ec120e53daba021d8102f3afc0d4b04fc3>) | autotools/m4: Probe for access_remote_vm and provide compat shim |
| | oot-backport/main | [`f04b19615`](<https://github.com/intel-gpu/xekmd-backports/commit/f04b19615f10a6045f6e889247211a6d82f1a715>) | autotools/m4: Manage const-qualified struct bin_attribute callbacks |
| | oot-backport/main | [`57cc766d5`](<https://github.com/intel-gpu/xekmd-backports/commit/57cc766d5946065110443e32c6a96f0700d05698>) | autotools/m4: Add KMAP_LOCAL gaurd to utilize in swap.h |
| | oot-backport/main | [`adf8db4ab`](<https://github.com/intel-gpu/xekmd-backports/commit/adf8db4ab33f1a5a11dccc0f9a7135285d3cd4e6>) | backport/compat: Add drm_dev_wedged_event compatibility |
| | oot-backport/main | [`a94d5ee15`](<https://github.com/intel-gpu/xekmd-backports/commit/a94d5ee15c2fa701ad6c9045601b2e81bb80c766>) | autotools/m4: Manage DRM_DEV_WEDGED_EVENT_NOT_PRESENT availability |
| | oot-backport/main | [`dea4a6bcd`](<https://github.com/intel-gpu/xekmd-backports/commit/dea4a6bcd851102590e5fd7e15773e78f0783b06>) | Install drm_gpusvm_helper module for debian package support |
| | oot-backport/main | [`2350e344d`](<https://github.com/intel-gpu/xekmd-backports/commit/2350e344da5e6c4c21ca10b36acffc586bbb0029>) | drm/scheduler: Use system_highpri_wq when percpu scheduler wq is absent |
| | oot-backport/main | [`d68455702`](<https://github.com/intel-gpu/xekmd-backports/commit/d68455702adf2bcd6566463f7ef232b966bcad07>) | drm/xe: Remove older put_pm label |
| | oot-backport/main | [`a344f0876`](<https://github.com/intel-gpu/xekmd-backports/commit/a344f0876917c462c6632280524941a780d89340>) | backport: Enable DRM_GPUSVM in defconfig and Makefile.kernel |
| | oot-backport/main | [`77e2b2b2a`](<https://github.com/intel-gpu/xekmd-backports/commit/77e2b2b2a637b0b071c1fdce676582d931fd8c18>) | autotools/m4: Add probe for migrate_device_pfns |
| | oot-backport/main | [`8036ae57f`](<https://github.com/intel-gpu/xekmd-backports/commit/8036ae57fea22f7b100b0693c7343ac74f6a2606>) | autotools/m4: Add probe for zone_device_page_init |
| | oot-backport/main | [`5e5168805`](<https://github.com/intel-gpu/xekmd-backports/commit/5e51688052ff4565566da0f1f1890de405ceace0>) | autotools/m4: Add probe for vma_alloc_folio |
| | oot-backport/main | [`f01ab024a`](<https://github.com/intel-gpu/xekmd-backports/commit/f01ab024a9391f8d65b26f86a4759bda74d780fd>) | autotools/m4: Add probe for folio_free |
| | oot-backport/main | [`b9ca24543`](<https://github.com/intel-gpu/xekmd-backports/commit/b9ca245435eea0d6b72cdb43f162609ffd52a0b1>) | autotools/m4: Add probe for for_each_if |
| | oot-backport/main | [`e3ff7db27`](<https://github.com/intel-gpu/xekmd-backports/commit/e3ff7db27cd1631efab8c88a70bfc235f68c12fe>) | autotools/m4: Add shrinker compat for older kernels |
| | oot-backport/main | [`705d817cb`](<https://github.com/intel-gpu/xekmd-backports/commit/705d817cb9702fa99c1f40b96faa2d5517d9bdcc>) | drm/pagemap, drm/xe: Drop drm_pagemap_put guard patches, use upstream definition |
| | oot-backport/main | [`b5077c0a3`](<https://github.com/intel-gpu/xekmd-backports/commit/b5077c0a3eff79f8dfe8a48daa4f7564ff3ff44c>) | backport: Provide ACQUIRE/ACQUIRE_ERR via cleanup.h shim |
| | oot-backport/main | [`63779416c`](<https://github.com/intel-gpu/xekmd-backports/commit/63779416cfe9ae0bb9ba4dc3e76b465515e1ffb1>) | backport: Inline dma_fence_check_and_signal_locked() in dma-fence.h |
| | oot-backport/main | [`12265af40`](<https://github.com/intel-gpu/xekmd-backports/commit/12265af40b21416a110c4fe8f8ea80d476642d97>) | backport: Inline PCI ReBAR helpers in pci.h |
| | oot-backport/main | [`de8e452a1`](<https://github.com/intel-gpu/xekmd-backports/commit/de8e452a12f1d43c438f486f6ae955c125725c8f>) | autotools/m4: Manage page_pgmap() helper availability |
| | oot-backport/main | [`0dbbd7aea`](<https://github.com/intel-gpu/xekmd-backports/commit/0dbbd7aeaa269294ed007886456c74a37d736434>) | kconf: fix kconf_id_lookup forward declaration and include placement |
| | oot-backport/main | [`81f6a1c5f`](<https://github.com/intel-gpu/xekmd-backports/commit/81f6a1c5fcd04ea15b7e416dea266b9b13c3750b>) | autotools/m4: Add drm_gpuvm_madvise_ops_create and drm_gpuvm_bo_obtain for lock |
| | oot-backport/main | [`369f3fbc1`](<https://github.com/intel-gpu/xekmd-backports/commit/369f3fbc14c5e81198bc9ba4298e9fef9a1196f7>) | autotools/m4: Manage DRM_PAGEMAP_PUT prototype availability |
| | oot-backport/main | [`bb2bde447`](<https://github.com/intel-gpu/xekmd-backports/commit/bb2bde44778d1cca440b79e1a6245a9059d1af0f>) | autotools/m4: Add DRM_MODE_SIZE_DUMB prototype availability |
| | oot-backport/main | [`c983c0f3c`](<https://github.com/intel-gpu/xekmd-backports/commit/c983c0f3ccd6f6deb1b4bdb997bf4cb8e27454d5>) | Add a callback to determine attribute visibility |
| | oot-backport/main | [`172ab73bb`](<https://github.com/intel-gpu/xekmd-backports/commit/172ab73bb9822ac35bebad76a676dc839171f9b3>) | Add __assign_str macro gets the length of string |
| | oot-backport/main | [`e3efc67dd`](<https://github.com/intel-gpu/xekmd-backports/commit/e3efc67dd9cbd80114ccfc184bfd2fb7133463bd>) | autools/m4: Manage PCI ReBAR helpers prototype availability |
| | oot-backport/main | [`071c8cd00`](<https://github.com/intel-gpu/xekmd-backports/commit/071c8cd0070f1b96db36b2b61e36f2e21d2f1e88>) | autotools/m4: Manage DMA_FENCE_CHECK_AND_SIGNAL_LOCKED signals availability |
| | oot-backport/main | [`1390b9a59`](<https://github.com/intel-gpu/xekmd-backports/commit/1390b9a59f80c577f442ceed9ba0acdebe3cb30c>) | Add poll_timeout_us macro to generalize I/O usecases |
| | oot-backport/main | [`57ab18aaa`](<https://github.com/intel-gpu/xekmd-backports/commit/57ab18aaa220506d3d312cbf40bd74ecf6b6967c>) | autotools/m4: Manage shmem_writeout() prototype availability |
| | oot-backport/main | [`5caec876b`](<https://github.com/intel-gpu/xekmd-backports/commit/5caec876bceb0f8bfa16902601cd429a70e5354c>) | autotools/m4: Manage init_llist_node interface prototype availability |
| | oot-backport/main | [`81a7f2df7`](<https://github.com/intel-gpu/xekmd-backports/commit/81a7f2df771d2209e55cddb883ac62e8bdf377ed>) | Move for_each_if() to util_macros.h for wider use |
| | oot-backport/main | [`09346250e`](<https://github.com/intel-gpu/xekmd-backports/commit/09346250eb736d83f3774c22795419488529b074>) | autotools/m4: Manage DEFINE_GUARD_COND prototype availability |
| | oot-backport/main | [`5854fb5c8`](<https://github.com/intel-gpu/xekmd-backports/commit/5854fb5c8e6ad370eda76deb41eab913b505d59a>) | autotools/m4: Manage ACQUIRE() and ACQUIRE_ERR() for conditional locks |
| | oot-backport/main | [`2a02c3eb3`](<https://github.com/intel-gpu/xekmd-backports/commit/2a02c3eb3e086ce4c3ea92921a1fe4ab98601ffa>) | autotools/m4: Manage VFIO_GET_REGION_INFO_CAPS availability |
| | oot-backport/main | [`d212a5d5f`](<https://github.com/intel-gpu/xekmd-backports/commit/d212a5d5f015beec865f47bba99f706fc3979acb>) | copy-list: Add drm_dumb_buffers.h and drm_pagemap_util.h |
| | oot-backport/main | [`4896dcab8`](<https://github.com/intel-gpu/xekmd-backports/commit/4896dcab8cf80afb918af87a7d9fbedae20bb721>) | autotools/m4: Add system_percpu_wq prototype availability |
| | oot-backport/main | [`ac6fc3765`](<https://github.com/intel-gpu/xekmd-backports/commit/ac6fc376550e9b3ef74e1f5bec293fb737b81ee6>) | autotools/m4: Manage huge_mnt member to inline drm_gem_huge_mnt_create() |
| | oot-backport/main | [`8d5ced02e`](<https://github.com/intel-gpu/xekmd-backports/commit/8d5ced02e328267182741bb919f36afd3fbb8112>) | autotools/m4: Manage EMPTY_VMA_FLAGS availability |
| | oot-backport/main | [`e553d8aa1`](<https://github.com/intel-gpu/xekmd-backports/commit/e553d8aa1112d6e357904a41163640ca1faa9c38>) | autotools/m4: Add slab allocation helpers for alloc_obj() |
| | oot-backport/main | [`03ea66c17`](<https://github.com/intel-gpu/xekmd-backports/commit/03ea66c178f95be1590536ccc10379600024db34>) | Fix hunk offsets in Makefile for v7.0-rc1 |
| | oot-backport/main | [`197410563`](<https://github.com/intel-gpu/xekmd-backports/commit/1974105632983b42b845d8e87e0143c83a71a675>) | Rebase the DRM_GPUVM on backport build flag |
| |  | Backport-only change | Readme: Fix Typo in doc |
| | drm-tip-eudebug | [`aa14a3b4b`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/aa14a3b4bbb073c5fc71ccc79f6400c67cf85473>) | drm/xe: Add EUDEBUG_ENABLE exec queue property |
| | drm-tip-eudebug | [`bee22cd9b`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/bee22cd9bda2892832a7ed05a545fdffd42ddad2>) | drm/xe: Add PRELIM infrastructure |
| | drm-tip-eudebug | [`946f4a15d`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/946f4a15d3d9cb64cc8b422b75e8715386abe14d>) | drm/xe: Attach debug metadata to vma |
| | drm-tip-eudebug | [`e7f9dd9cc`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/e7f9dd9ccc7660babbf1c7654ac183ba2de7d241>) | drm/xe: Debug metadata create/destroy ioctls |
| | drm-tip-eudebug | [`a37d1d883`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/a37d1d883359a8482cb27d07ceea6c0eb3edcaee>) | drm/xe: Implement SR-IOV and eudebug exclusivity |
| | drm-tip-eudebug | [`b476daba4`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/b476daba4f313c30239484ac355b2781dd7ae0c3>) | drm/xe: Reset engines before gt reset |
| | drm-tip-eudebug | [`431490a44`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/431490a44aa690dc3cc3c220cbf5f834cd27a94b>) | drm/xe/eudebug: Add UFENCE events with acks |
| | drm-tip-eudebug | [`0325306f1`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/0325306f12bc80defca26b8a4195795d472bb2ae>) | drm/xe/eudebug: Add debug metadata support for xe_eudebug |
| | drm-tip-eudebug | [`091a0aa03`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/091a0aa0321f8d3b0b2fdec6c5d7cd8157b73d53>) | drm/xe/eudebug: Add read/count/compare helper for eu attention |
| | drm-tip-eudebug | [`b0f174b74`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/b0f174b74f7b08c681ef6db22d0b24058e441a04>) | drm/xe/eudebug: Add vm bind and vm bind ops |
| | drm-tip-eudebug | [`5e7683a73`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/5e7683a73696f7ce35e8139ee395e2cacf1df533>) | drm/xe/eudebug: Apply Wa_14024339748 to xe3p_lpg |
| | drm-tip-eudebug | [`ecab48471`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/ecab484710fbd81e99736988fcc4fd35d9b3f8f8>) | drm/xe/eudebug: Dynamically toggle debugger functionality |
| | drm-tip-eudebug | [`ccfe0f20d`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/ccfe0f20da335962ee0516a13e25b61c435c883c>) | drm/xe/eudebug: Enable EU pagefault handling |
| | drm-tip-eudebug | [`f229bb077`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/f229bb0776b3fb9285af6883a30380bbc7003ca0>) | drm/xe/eudebug: Implement vm_bind_op discovery |
| | drm-tip-eudebug | [`9f71a01d9`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/9f71a01d99d2bc728a5eea70c16fc09a1c3e888f>) | drm/xe/eudebug: Introduce EU control interface |
| | drm-tip-eudebug | [`7a0c384f1`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/7a0c384f114ce8ff2d2eac1ac55af1fb2c28d6f9>) | drm/xe/eudebug: Introduce EU pagefault handling interface |
| | drm-tip-eudebug | [`72d7c7659`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/72d7c76597410b0add2159092c1ab3283560d1dc>) | drm/xe/eudebug: Introduce discovery for resources |
| | drm-tip-eudebug | [`fd2f4b3dc`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/fd2f4b3dcd06ff90cfce7b938f5cb1e0b519a065>) | drm/xe/eudebug: Introduce eudebug support |
| | drm-tip-eudebug | [`7b2b75faf`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/7b2b75faf8d29c5689dc7fe1e79b0edc8b451661>) | drm/xe/eudebug: Introduce exec queue placements event |
| | drm-tip-eudebug | [`07b6f4cb5`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/07b6f4cb541d6fd34c63a991c87454c65c6c34a5>) | drm/xe/eudebug: Introduce exec_queue events |
| | drm-tip-eudebug | [`0fb00ea4a`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/0fb00ea4a4fad06214c1efc05d10760f397451ca>) | drm/xe/eudebug: Introduce per device attention scan worker |
| | drm-tip-eudebug | [`e67781291`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/e67781291ae461975057a03d678023f43127b704>) | drm/xe/eudebug: Mark guc contexts as debuggable |
| | drm-tip-eudebug | [`df0d510db`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/df0d510db5a08c9d4fd3d8ce5f67ac7d2baecc7c>) | drm/xe/eudebug: Prelim rework for Xe EU debug |
| | drm-tip-eudebug | [`da6f2ca8f`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/da6f2ca8f813cb825c1e250642d2cc0a19c6e731>) | drm/xe/eudebug: add eudebug drm managed finalize |
| | drm-tip-eudebug | [`7305cacd6`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/7305cacd6b2936b48b9fbffdfbc65b283e7d8b75>) | drm/xe/eudebug: hw enablement for eudebug |
| | drm-tip-eudebug | [`bffb950b1`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/bffb950b1b47f0039aa71d9b54365acaf679b3af>) | drm/xe/eudebug/ptl: Add RCU_DEBUG_1 register support for xe3 |
| | drm-tip-eudebug | [`8e4e6ae84`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/8e4e6ae84dc7ba2ddd3b6a3adc9809be81e1daa6>) | drm/xe/eudebug/ptl: Add support for extra attention register |
| | drm-tip-eudebug | [`58a67b8e3`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/58a67b8e3449ab73e70b5cbe591bac3c7dbda0b8>) | drm/xe/eudebug: userptr vm access pread/pwrite |
| | drm-tip-eudebug | [`1f5c37a54`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/1f5c37a54b2c4018c73d7735bdde057b1804a897>) | drm/xe/eudebug: vm open/pread/pwrite |
| | drm-tip-eudebug | [`3daeea6e4`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/3daeea6e4edcc4771f4fe96cf45c1828070579ba>) | drm/xe/eudebug/xe3p: Pagefault exception debugging support |
| | drm-tip-eudebug | [`d9e93b23b`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/d9e93b23b06455b2d037ce090551a729f4ee4265>) | drm/xe/eudebug/xe3p: Per context debugging support |
| | drm-tip-eudebug | [`07100da23`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/07100da23348a6c2a413cd10d471485ccab530dc>) | drm/xe/eudebug_test: Introduce xe_eudebug wa kunit test |
| | drm-tip-eudebug | [`54525a630`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/54525a630b1c6d3d63e914a8590924573dc53a70>) | drm/xe/guc_actions_abi/xe3: Add GUC EU Debug bits |
| | ML v3 | [Patchwork](<https://patchwork.freedesktop.org/patch/555006/?series=120480&rev=3>) | &#91;TEMP&#93; drm/xe/vm: Support for adding null page VMA to VM on request |
| | drm-tip-eudebug | [`f922a77a2`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/f922a77a2c00ff4336ff887d5f167930aad0fdb1>) | drm/xe/xe3p: disable EU thread hang on exception |
| | drm-tip-eudebug | [`1eb860f06`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/1eb860f066d8a71f4e56f569dfc08657f5d0e231>) | drm/xe/xe_file: change pid type from pid_t to pid pointer |
| | drm-tip-eudebug | [`7cc9a2bc6`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/7cc9a2bc62da948567ca531190fc7365b1ae4adb>) | fixup! drm/xe/eudebug: Prelim rework for Xe EU debug |
| | drm-tip-eudebug | [`81a0843b1`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/81a0843b1b211787d4c2fb279815521be9ba08ac>) | fixup! drm/xe/eudebug: Prelim rework for Xe EU debug |
| | drm-tip-eudebug | [`060412dcd`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/060412dcdcb1f6ee0dd1d0de827f64d562eb5493>) | fixup! drm/xe/eudebug/xe3p: Per context debugging support |
| | drm-tip-eudebug | [`53dcfd28f`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/53dcfd28fd15443fae784d76376275e858bcbb80>) | fixup! drm/xe/vma: Modify new_vma to accept struct xe_vma_mem_attr as parameter |
| | drm-tip-eudebug | [`32f4488a5`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/32f4488a5e173562c6d2fe9d530133839550dcd5>) | mm: export access_remote_vm symbol for debugger use |
| | drm-tip-eudebug | [`a5e9f6abf`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/a5e9f6abf20c83189665a7476c5bf3f0ee50e56c>) | ptrace: export ptrace_may_access |
| | xe-next | [`ee18d39a0`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/ee18d39a087792d7c11e6e87b546aff435a3cc58>) | drm/drm_ras: Add clear-error-counter netlink command to drm_ras |
| | xe-next | [`31f855a47`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/31f855a47c8beb8fee7d74374c9d21ba9ab06700>) | drm/xe: Add IRQ page to HW engine definition |
| | xe-next | [`d0672008c`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/d0672008cde3a8616c517d53d657300dce3c36a7>) | drm/xe: Set GT rp min frequency as 1.2GHz default for BMG/CRI |
| | xe-next | [`e68a60f9e`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/e68a60f9e6a602684f335ede8af1170c13998b37>) | drm/xe/cri: Add new PCI IDs |
| | xe-next | [`ead21111e`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/ead21111e275c89828dc13ac8cfa657971ec874c>) | drm/xe/hw_error: Cleanup array map |
| | xe-next | [`c973f7a67`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/c973f7a672d07b9c297c27011bab299bc61732ba>) | drm/xe/hwmon: Enable energy attributes for CRI |
| | xe-next | [`ffc2f7fd1`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/ffc2f7fd1c2b39ef50dd92556232deec653fc466>) | drm/xe/hwmon: Read accepted power limit for CRI |
| | xe-next | [`17e974818`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/17e974818cd7313ed0d2697c0c5b9c600c9a939b>) | drm/xe/memirq: Drop cached iosys_map for MEMIRQ mask |
| | xe-next | [`8d8395e94`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/8d8395e943129b457403030d1112a1f9e48b6c27>) | drm/xe/memirq: Drop cached iosys_map for MEMIRQ status |
| | xe-next | [`4c3077da4`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/4c3077da4e100679d8e5d6e463746de0dd22bdfa>) | drm/xe/memirq: Dump all source pages if MSI-X |
| | xe-next | [`2ddedd4b7`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/2ddedd4b7b7c329dd65358025cba8652675bec3d>) | drm/xe/memirq: Enable GT_MI_USER_INTERRUPT only |
| | xe-next | [`e89b59652`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/e89b59652ccb0987c8f4647b4e7062516880756d>) | drm/xe/memirq: Make page layout macros private |
| | xe-next | [`86d08fe94`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/86d08fe942680bea5f77b414748a78a1ad7613f3>) | drm/xe/memirq: Reduce buffer size |
| | xe-next | [`0be1268ef`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/0be1268ef0a0043b594b7cf95e9ed53f5e0a7d12>) | drm/xe/memirq: Update GuC initialization and IRQ handler |
| | xe-next | [`becd6a78b`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/becd6a78b56152ec95a34514ee0569fea477b5d0>) | drm/xe/memirq: Update diagnostic message |
| | xe-next | [`37f1856e1`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/37f1856e124b4b18e48ad59995c6dd70cfcb782b>) | drm/xe/memirq: Use IRQ page from HW engine definition |
| | xe-next | [`8555fb847`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/8555fb84749c16d799caad0c5997c183bcefd0da>) | drm/xe/oa: Add val arg to xe_oa_is_valid_config_reg |
| | xe-next | [`c59395e21`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/c59395e215b950dd7bb5ac7236d16e4be58f4040>) | drm/xe/oa: Implement Wa_14026633728 |
| | xe-next | [`dc4f643c1`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/dc4f643c1c2f6929f78b7f002d281411b81952e8>) | drm/xe/oa: MERTOA Wa_14026746987 |
| | xe-next | [`160c1af4f`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/160c1af4fbb66ad887825eda5601eccd386015f8>) | drm/xe/oa: MERTOA Wa_14026779378 |
| | xe-next | [`15e31865c`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/15e31865ce3329e07fe634f4a75bceb3a4ad778a>) | drm/xe/oa: Refactor oa_unit_supports_oa_format |
| | xe-next | [`41255b2f1`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/41255b2f1e03b7f949c6b9b491f789d7ea9c49a3>) | drm/xe/oa: Use drm_gem_mmap_obj for OA buffer mmap |
| | xe-next | [`7b5c60226`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/7b5c60226753e5cd43073ff1dad5d1b983691521>) | drm/xe/oa: Use xe_map layer |
| | xe-next | [`d34b42ffb`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/d34b42ffb1dd15603fd20fb8c59891fd30e5988d>) | drm/xe/ras: Introduce correctable error handling |
| | xe-next | [`21677c5ea`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/21677c5ea98ac16657c572b4a0dee6893ecda1c6>) | drm/xe/sysctrl: Add system controller event support |
| | xe-next | [`a68247371`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/a68247371b6eb33013429037b28ff713aa60fc5a>) | drm/xe/sysctrl: Add system controller interrupt handler |
| | xe-next | [`36acdfbc2`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/36acdfbc2cad67f550021725d6550bb0d4973217>) | drm/xe/xe3p: add gt tuning TileY 2x2 walk pattern |
| | linux-next | [`c027f1a19`](<https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=c027f1a19180ea4e5aa29bab4e0871a21bb96c05>) | drm/xe/xe3p_lpg: Add Wa_18044193044 |
| | xe-next | [`e12be2535`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/e12be2535cca2e0b457175a0ee25d1c0d1fb909f>) | drm/xe/xe_drm_ras: Add support for clear-error-counter in XE drm_ras |
| | xe-next | [`a902767f9`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/a902767f91ba9818b792f1137d3a835310c7d265>) | drm/xe/xe_pci: Enable System Controller support on CRI platform |
| | xe-next | [`37ace5254`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/37ace5254a2b1520753762527365ecad7fad797a>) | drm/xe/xe_sysctrl: Add ABI and mailbox interface headers |
| | xe-next | [`5ea3f0dc8`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/5ea3f0dc8f9d33adf72532b366d0b7b91dae4d7f>) | drm/xe/xe_sysctrl: Add System Controller initialization support |
| | xe-next | [`1f95f6181`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/1f95f618182b5c99d46378141e0fb84f09bf914b>) | drm/xe/xe_sysctrl: Add System Controller mailbox communication support |
| | xe-next | [`281a79f78`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/281a79f78dfedf10f6c7de4334434c38eb5459dd>) | drm/xe/xe_sysctrl: Add System Controller mailbox register definitions |
| | xe-next | [`02eca6edc`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/02eca6edcb324bc37495930c344e235a90f42d72>) | drm/xe/xe_sysctrl: Add System Controller power management support |
| | xe-next | [`bb2447ef6`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/bb2447ef6aee314f303b1a8e0ede6b98c8f6a529>) | drm/xe/xe_sysctrl: Add System Controller types and device integration |
| | xe-next | [`45334d5c3`](<https://gitlab.freedesktop.org/drm/xe/kernel/-/commit/45334d5c364498629b314391c7d1eac0b64c882f>) | drm/xe/xe_sysctrl: Drop redundant endian conversions in mailbox header macros |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/682633/?series=156297&rev=1>) | &#91;TEMP&#93; topic/for-xe-CI: drm/xe/cri: Define GuC firmware for CRI |
| | ML v2 | [Patchwork](<https://patchwork.freedesktop.org/patch/697586/?series=159711&rev=2>) | &#91;TEMP&#93; topic/for-xe-CI: drm/xe/cri: Define GuC firmware for CRI |
| | ML v1 | [Patchwork](<https://patchwork.freedesktop.org/patch/729254/?series=167572&rev=1>) | &#91;TEMP&#93; topic/for-xe-CI: drm/xe/cri: Define GuC firmware for CRI |
| | drm-tip-eudebug | [`865a5da97`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/865a5da9722d80aa8495cf4f893ed13afe4f7154>) | drm/xe/xe3p: disable EU thread hang on exception |
| | drm-tip-eudebug | [`852ec9ae5`](<https://github.com/mpatelcz/drivers.gpu.linux-xe.kernel/commit/852ec9ae5909ca0b4a213d5bd06f34c0826f5cac>) | drm/xe: Add EUDEBUG_ENABLE exec queue property |
