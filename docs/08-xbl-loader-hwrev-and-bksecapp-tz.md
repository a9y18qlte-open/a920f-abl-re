# SM-A920F (`a9y18qlte`) `XBL_Loader`, `XBL_Ramdump`, `VerifiedBootDxe`, `TzDxe`, and `bksecapp` TrustZone Architecture

**Target Firmware**: Samsung Galaxy A9 2018 (`SM-A920F`, `a9y18qlte`, SDM660) — `A920FXXS7CVH1` (`SignerVer02`, Signer ID `55622970R`, `2022-08-26`)  
**Verification Script**: [`scripts/analyze_xbl_loader_bksecapp.py`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/scripts/analyze_xbl_loader_bksecapp.py)

---

## 1. `XBL_Loader` & `XBL_Ramdump` (`xbl_loader.elf`)

### 1.1 ELF64 Container & Memory Layout

[`xbl.elf`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/xbl.elf) (`2,840,100` bytes, SHA-256 `c5dcec89f2ffa937cbd488c254bccfc1056a1da9425222b6a7c8e5c630514394`) is an `ELFCLASS64` (`EM_AARCH64`) image with `16` program headers, entry point **`0x14021c90`**, an MBN v5 hash/certificate segment (`PHDR[1]`, `cert[0]` `SW_ID = 0000000700000000`, `HW_ID = 3006000000200000` SDM660, `OEM_ID = 0020` Samsung), and a `512`-byte `SignerVer02` footer at `0x2b5424`. In [`xbl_loader.elf`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/xbl_loader.elf), `PHDR[12]` (`UEFI FD` at `0x9fc00000`) is set to `PT_NULL` so Ghidra loads `XBL_Loader`, `XBL_SEC` stubs, and `XBL_Ramdump` cleanly ([`xbl_mbn_metadata.json`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/xbl_mbn_metadata.json)):

| PHDR | Type | File Offset | VAddr / PAddr | FileSz | MemSz | Flags | Component Role |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `0` | `PT_NULL` | `0x0` | `0x0` | `0x3c0` | `0x0` | `0x7000000` | ELF64 header + 16 PHDRs |
| `1` | `PT_NULL` | `0x1000` | `0x9fdb6000` | `0x1b28` | `0x2000` | `0x2200000` | Qualcomm MBN v5 hash table (`code_size=0x200`) + 3×X.509 DER certs (`Samsung Root CA`) |
| `2` | `PT_LOAD` | `0x3000` | **`0x14699000`** | `0x131c0` | `0x131c0` | `0x5000005` (`R\|X`) | **`XBL_SEC`** (IMEM EL3/secure monitor code) |
| `3` | `PT_LOAD` | `0x161c0` | **`0x14015000`** | `0x516d0` | `0x516d0` | `0x5` (`R\|X`) | **`XBL_Loader`** `.text` (RPM/Boot IMEM / L2/OCIMEM; `VBAR_EL1 = 0x14015000`) |
| `4` | `PT_LOAD` | `0x67890` | `0x14077000` | `0x0` | `0x3000` | `0x6` (`R\|W`) | `XBL_Loader` `.bss` / ZI cleared in `entry` (`0x14021c90`) |
| `5` | `PT_LOAD` | `0x67890` | `0x1407a000` | `0x81bc` | `0x81bc` | `0x6` (`R\|W`) | `XBL_Loader` `.data` (`sbl1_init_funcs`, `sbl1_config_table`, vtables) |
| `6` | `PT_LOAD` | `0x6fa50` | `0x14085000` | `0x0` | `0x14000` | `0x6` (`R\|W`) | `XBL_Loader` runtime ZI / stack / heap |
| `7` | `PT_LOAD` | `0x6fa50` | `0x85e00000` | `0x0` | `0x276a0` | `0x6` (`R\|W`) | DDR page tables (`0x85e00000`), DDR boot log (`0x85e11000`), `sbl_if_shared_info` (`0x85e12140`) |
| `8` | `PT_LOAD` | `0x6fa50` | **`0x146ae000`** | `0x2e30` | `0x2e30` | `0x5` (`R\|X`) | **`XBL_SEC` SMC trampoline** (`FUN_146ae000`) |
| `9` | `PT_LOAD` | `0x72880` | `0x146b1000` | `0xb64` | `0xb64` | `0x6` (`R\|W`) | `XBL_SEC` `.data` (`0x146b1c00` entry/arch state) |
| `10` | `PT_LOAD` | `0x733f0` | `0x14099000` | `0x1a1a8` | `0x1a1a8` | `0x7` (`R\|W\|X`) | Secondary loader / driver `.text+.data` (`PMIC` / `DAL` / `DDR`) |
| `11` | `PT_LOAD` | `0x8d5a0` | `0x146b2000` | `0x0` | `0x48ec` | `0x6` (`R\|W`) | `XBL_SEC` ZI (cleared to `0x9000` bytes at `0x1402287c`) |
| `12` | `PT_LOAD`* | `0x8d5a0` | **`0x9fc00000`** | `0x1b5800` | `0x1b5800` | `0x7` (`R\|W\|X`) | **`UEFI FD`** (Outer FV containing `Sec.te`, `uefiplat.cfg`, and gzipped `inner_dxe_fv.bin`) |
| `13` | `PT_LOAD` | `0x242da0` | **`0x85e35000`** | `0x6add8` | `0x6add8` | `0x5` (`R\|X`) | **`XBL_Ramdump`** `.text` (`XBLRamDumpMain` @ `0x85e357a8`) |
| `14` | `PT_LOAD` | `0x2adb80` | `0x85ebc000` | `0x78a4` | `0x43d0c` | `0x6` (`R\|W`) | `XBL_Ramdump` `.data` + `.bss` |
| `15` | `PT_LOAD` | `0x2b5430` | `0x85eab000` | `0x0` | `0xd750` | `0x6` (`R\|W`) | `XBL_Ramdump` DDR ZI (`0x85eab000`) |

> \*`PHDR[12]` is `PT_LOAD` in `xbl.elf` and patched to `PT_NULL` in `xbl_loader.elf`.

### 1.2 Boot Sequence up to `UEFI FD` (`0x9fc00000`) & `ABL` ELF/MBN Loading

1. **Entry & SBL1 Main Control (`entry` @ `0x14021c90` -> `FUN_1402287c` in `sbl1_mc.c`)**:
   - Sets `VBAR_EL1 = 0x14015000`, clears `DAIF` abort mask, zeroes `0x14077000` (`0x3000` bytes), and jumps to `FUN_1402287c(bl_shared_data)`.
   - Captures initial MPM2 sleep counter (`_DAT_010a3000`), halts if debug magic `_DAT_146bf944 == 0x53444247` (`"SDBG"`), initializes PBL shared data (`DAT_1408e630`), copies the `0x58`-byte `sbl_if_shared_info` (`DAT_1408e5d8`), sets up the `0x100`-byte authentication/hash record buffer at `DAT_1407c4a0 + 0x834`, calls `FUN_14022514` (loads `XBL_SEC` segments & MMU entries), and logs `"SBL1, Start"`.
   - Calls `FUN_14037348(&DAT_1408e630, &DAT_1407ad38, ...)` and executes the SBL1 init pipeline (`0x1407a610..0x1407a760`):
     - `0x1407a660`: `0x1402326c` (`pm_device_init`, `pm_driver_init`, 7s DVDD/PMIC reset configuration based on param debug level `0x574f4c44` `"DLOW"` vs Warm Reset, `vsense_init`).
     - `0x1407a668`: `0x140234a8` (`sbl1_ddr_set_params`, CDT parse via `FUN_1402d82c`, `Pre_DDR_clock_init`, `/dev/icbcfg/boot`, `sbl1_hw.c` DDR training via `FUN_14023664` -> `FUN_14022188`).
     - `0x1407a670`: `0x14022e50` (DDR training + Samsung `"NAD USER DDR test"` check).
     - `0x1407a6c0`: `0x14024694` (`boot_dload_check` — checks EDL/upload cookies & key combos; invokes `PTR_FUN_1407a5d0` -> `0x1402416c` to enter EDL on dload/upload trigger, while `0x14022c9c` in `sbl1_target.c` loads/enters `XBL_Ramdump`; see §1.4).
     - `0x1407a6c8`: `0x140362b8` (`boot_smem.c` SMEM init).
     - `0x1407a6d0`: `0x140258a4` (populates **SMEM `0x86`** and **SMEM `0x87`**).
     - `0x1407a6d8`: `0x1402403c` (allocates SMEM `0x25a` `0x2800` bytes).
     - `0x1407a708`: `0x140366dc` (`boot_ram_partition.c` — populates **SMEM `0x192`** `0x918` bytes, magic `0xaf9ec4e29da5e0a8`, version `2`).
     - `0x1407a730`: `0x1402235c` (`"SEC Image Loaded, Delta"`).
   - Flushes cache across all SBL1/SMEM/XBL_SEC/Ramdump regions (`FUN_140331fc`) and invokes `FUN_14034fa4(&DAT_1408e630, 0x15, &DAT_1407a768)` (`boot_config_process_bl` in `boot_config.c`).

2. **`sbl1_config_table` (`0x1407a768`, 9 entries × `0x90` stride) & MBN/ELF Loading (`FUN_14034aa8` @ `0x14034aa8`)**:
   Each entry loads and authenticates a signed Qualcomm ELF/MBN image (`FUN_14035020` MBN hash/X.509 cert verification + `FUN_14037060` -> `0x14037a34` metadata verify, `FUN_14036bc4` appends `0x30`-byte measurement to `DAT_1407c4a0 + 0x834` / SMEM `0x50`, `FUN_140359ec` loads `PT_LOAD` segments via `boot_elf_loader.c` and verifies segment hashes via `FUN_140370a4`):

   | Index | `image_type` | Partition GUID (`0x1407c3c0..0x1407c470`) | Pre / Post / Exec Hooks | Log String & Role |
   | --- | --- | --- | --- | --- |
   | `0` | `0x16` | `c00eef24-7709-43d6-9799-dd2b411e7a3c` (`pmic`) | `pre=0x1407a650`, `post=0x14023858` | `"PMIC Image Loaded, Delta"` (`0x217000`, `0x207000` PMIC ELF cfg) |
   | `1` | `0x200` | `e6e98da2-e22a-4d12-ab33-169e7deaa507` (`apdp`) | `pre=0x1407a6a0`, `post=0x14023874` | `"APDP Image Loaded, Delta"` (enabled only if `apdp` partition present) |
   | `2` | `0x5` | `f65d4b16-343d-4e25-aafc-be99b6556a6d` (`devcfg`) | `pre=0x1407a730`, `post=0x14023904` | `"QSEE Dev Config Image Loaded, Delta"` |
   | `3` | `0x7` | `a053aa7f-40b8-4b1c-ba08-2f68ac71a4f4` (`tz`) | `pre=0x1408a460` | `"QSEE Image Loaded, Delta"` |
   | `4` | `0x15` | `e1a6a689-0c8d-4cc6-b4e8-55a4320fbd8a` (`hyp`) | — | `"QHEE Image Loaded, Delta"` |
   | `5` | `0xa` | `098df793-d712-413d-9d4e-89d711772228` (`rpm`) | `post=0x14023948` | `"RPM Image Loaded, Delta"` (skipped if Dload mode & security=0) |
   | `6` | `0x11` | `aa9a5c4c-4f1f-7d3a-014a-22bd33bf7191` (`sti`) | `exec=0x1402398c`, `post=0x14023aec` | `"STI Image Loaded, Delta"` (disabled if secure fuses blown) |
   | `7` | **`0x1c`** | `bd6928a1-4ce0-a038-4f3a-1495e3eddffb` (**`abl`**) | `post=0x14023c0c`, target `0x9fc00000` | `"ABL Image Loaded, Delta"`; triggers `FUN_14036ee4` TIMA 2.0 hash export! |
   | `8` | **`0x9`** | `400ffdcd-22e0-47e7-9a23-f16ed9382388` (**`APPSBL` / `XBL_Core`**) | `exec=0x14023c9c`, `pre=0x1407a758`, `post=0x14023ee0` | `"APPSBL Image Loaded, Delta"`, target `0x9fc00000` (`UEFI FD`) |

   - **TIMA 2.0 Bootloader Measurement Export (`FUN_14036ee4` @ `0x14036ee4`)**: Triggered when `image_type == 0x1c` (`abl`). Zeroes `0x9f800000` (`0x1000` bytes) and `0x9f900000`/`0x9f980000`/`0x9f880000`/`0x9f831000`, writes magic `"TIMA 2.0"` (`0x302e3220414d4954`) at `0x9f800000`, `count` (`6`) at `0x9f800008`, and copies up to `6` 32-byte image hashes at `0x9f800020` for image types matching bitmask `0x102004a1` (`0x0` XBL, `0x5` devcfg, `0x7` TZ, `0xa` RPM, `0x15` HYP, `0x1c` ABL). Later, `LinuxLoader.efi` (`0x8dc8`) invokes `bksecapp` command `0xc`, which maps `0x9f800000` to append the 7th (`boot`) measurement!
   - **QSEE Cold-Boot Handoff (`FUN_14023c9c` @ `0x14023c9c`)**: Entry `[8]` (`APPSBL` / `XBL_Core` at `0x9fc00000`) maps `0x14680000` (`0x19000`) and `0x1c000000` (`0x200000`), resolves QSEE (`type=7`) entry point into `_DAT_146b1c00`, copies `0x558` bytes of `bl_shared_data` into `0x85e12140`, sets `DAT_1407c4a0 + 0x44 = 0`, and invokes **`FUN_146ae000(0x82000114, 0x22, &DAT_85e12140, 0x558, 0, 0, 0, 0)`** (`XBL_SEC` EL3 QSEE cold-boot SMC), which initializes TrustZone/QSEE and drops to EL2 `UEFI FD` (`0x9fc00000`) to run `Sec.te` + DXE drivers and launch `LinuxLoader.efi` from `"ABOOT FV"` (`0x9fa00000`).

### 1.3 `hw_rev` Sampling (SMEM `0x87`) & LPDDR4 Vendor/Geometry (SMEM `0x86`)

Both Samsung vendor SMEM items are populated in **`FUN_140258a4`** (`0x140258a4`, called via init table slot `0x1407a6d0`):

1. **Board Hardware Revision `hw_rev` -> SMEM `0x87` (`SMEM_ID_VENDOR1`)**:
   - **Sampling (`FUN_14025860` @ `0x14025860`)**: Does **not** use PMIC ADC; instead initializes the **`kts1620_i2c`** 24-bit I2C GPIO expander (`"kts1620_i2c"`, I2C slave **`0x44`**, vtable `0x1407aff0`, init `FUN_14025a58`, pin reader `FUN_14025b80`) and reads pins **`0x15` (`21`)**, **`0x16` (`22`)**, and **`0x17` (`23`)**:
     ```c
     hw_rev = pin(21) | (pin(22) << 1) | (pin(23) << 2);  // 3-bit revision (0..7)
     ```
   - **SMEM `0x87` Layout (`0x98` bytes allocated via `smem_alloc` `FUN_1402b51c(0x87, 0x98)`)**:
     - `+0x00` (`8` B): `0x314e4556314e4556` (`"VEN1VEN1"`)
     - `+0x08` (`8` B): `4`
     - `+0x10` (`8` B): `(uint64_t)(hw_rev & 0xffffffff)` — logged as `"HW REV:%d"` and read directly by ABL `LinuxLoader.efi` at `0x16650` (`*(uint64_t *)(addr + 0x10)`).
     - `+0x60` (`4` B): `FUN_1402d67c()` -> `*(uint32_t *)(DAT_1407c058 + 0x55c)` (from DDR shared struct at `0x2a2000`).

2. **LPDDR4 Vendor & Geometry -> SMEM `0x86` (`SMEM_ID_VENDOR0`)**:
   - During `sbl1_ddr_set_params` (`FUN_140234a8`), `FUN_1402d82c` validates the CDT/DDR parameters (`magic = 0x44445200` `"DDR\0"`, version `2`) and populates the DDR shared struct at **`DAT_1407c058` (`0x2a2000`)** (`+0x1c` = `0x3c`-byte `device_params`, `+0x58` = `0x3c`-byte secondary params, `+0x94` = `0x9c`-byte LPDDR4 config).
   - **SMEM `0x86` Layout (`0x60` bytes allocated via `FUN_1402b51c(0x86, 0x60)`)**:
     - `+0x00` (`8` B): `0x304e4556304e4556` (`"VEN0VEN0"`)
     - `+0x08` (`8` B): `2`
     - `+0x10` (`4` B): Packed DDR descriptor returned by `FUN_1402d654()`:
       ```c
       ddr_word = ((*(uint32_t *)(0x2a2054) >> 10) << 24)
                | (uint32_t)(*(uint8_t *)(0x2a201c))          // JEDEC Manufacturer ID (bits [7:0])
                | ((*(uint32_t *)(0x2a204c) & 0xff) << 8)
                | ((*(uint32_t *)(0x2a2050) & 0xff) << 16);
       ```
     - **`FUN_1402d630`** resolves the low byte (`id & 0xff`) via lookup table **`0x1407b588`**: `1` = `"Samsung"`, `5` = `"Nanya"`, `6` = `"SK hynix"`, `8` = `"Winbond"`, `9` = `"ESMT"`, else `"unknown"`, logging `"DDR vendor:%s@%p"`. ABL `LinuxLoader.efi` (`0x16554`) copies `0x60` bytes from SMEM `0x86`.
   - Additionally, `boot_ddr_info.c` (`FUN_140363f4` / `FUN_1403661c` / `FUN_14036690`) populates per-channel DDR base/size descriptors from `0x1408a808..0x1408a830` (`FUN_1402e428` / `FUN_1402e43c`) into **SMEM `0x192`** (`FUN_140366dc`, `0x918` bytes).

### 1.4 EDL (`0x01FD3000`), `Shared_IMEM` (`0x146BF000`) Cookies & `XBL_Ramdump`

Cross-referenced with [`uefiplat.cfg`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/uefiplat.cfg):

- **EDL / Dload Register (`0x01FD3000`, `TCSR_BOOT_MISC_DETECT` / `DloadCookieAddr`)**:
  - **Bits `[5:4]` (`0x30`, `DloadCookieValue = 0x10`)**: Checked by `FUN_1402413c` (`(_DAT_01fd3000 & 0x30) != 0`) and cleared by `FUN_140240b0` (`"TCSR reg value 0x%x "`, `_DAT_01fd3000 &= 0xffffffcf`). Set by `FUN_14024154` (`_DAT_01fd3000 |= 0x10`) before reset (`FUN_14030d80(1)`) to request Ramdump/Dload mode.
  - **Bits `[3:0] = 0x1` (EDL / PBL Forced Download)**: Set by `FUN_1402416c` (`_DAT_01fd3000 = (_DAT_01fd3000 & 0xfffffff0) | 1; FUN_14030d80(1)`). Triggered in `FUN_14024694` when `FUN_140244f0` detects the 3-second volume-key sequence on a `USER` binary (`"@ Enter EDL MODE by volumn key at USER BINARY !!"`).

- **`Shared_IMEM` (`0x146BF000`, `SharedIMEMBaseAddr`) Cookies**:
  - `0x146BF01C` (`+0x1C`): `MemoryCaptureModeOffset`
  - `0x146BF024` (`+0x24`): `AbnormalResetOccurredOffset`
  - `0x146BF028` (`+0x28`): `GCCResetValueAddress`
  - `0x146BF0CC` / `0x146BF150`: Boot logger / IMEM magic (`0x61945374`)
  - `0x146BF650`: Upload/Dload status cookie (`0xdee1`, `0xcacec00c`, `0xdeadc00d` / `-0x21522ff3`, `0xbaddb055`, `0xcafebabe`, cleared on normal cold reset in `FUN_14030d80`)
  - `0x146BF65C`: Samsung Upload Magic **`0x776655ee`** (read/cleared by `FUN_140254b4`, checked by `FUN_140254d4`)
  - `0x146BF66C`: Samsung Upload Cause (`FUN_1402548c`, reset to `0xcafebabe`; decoded in `FUN_14024194` & `XBL_Ramdump` into reset reason `rr_data` and HTML summary causes `0x22`, `0x2f`, `0x75`, `0x85`, `0x88`, `0xb5`, `200`, `0xcc`, `0xee`, `0x5ac`, `0x5b1`, `0xdba`, `0xdbe`, `0x5dbe`, `0x9890`, `0xff`)
  - `0x146BF764`, `0x146BF7A4`, `0x146BFB14`: Samsung AP/CP/Subsys health & debug flags read by `FUN_14024194`
  - `0x146BF944`: `0x53444247` (`"SDBG"` JTAG halt loop in `FUN_1402287c`)

- **`XBL_Ramdump` (`0x85e35000`, `XBLRamDumpMain` @ `0x85e357a8` in `XBLRamDump.c`)**:
  - `FUN_14024694` (`boot_dload.c`) reads PMIC/GPIO keys (`PWR`, `INT`, `DN`, `UP`), reads Samsung `param` debug level at `0xb00000` (`0x574f4c44` = `"DLOW"` LOW) via `ss_common.c` (`FUN_14024c14`), evaluates PMIC PON & `Shared_IMEM` `0x146BF65C` (`0x776655ee`) in `FUN_14024194`, and writes the 2-char reset reason (`SP`/`WP`/`DP`/`KP`/`MP`/`PP`/`RP`/`BP`/`NP`/`TP`) to `0x2010`.
  - In `sbl1_target.c` (`FUN_14022c9c` @ `0x14022c9c`), `XBL_Loader` configures the `XBL_Ramdump` region (`&DAT_1407a508` / `&PTR_thunk_FUN_85e357a8_1407a598` via `FUN_14034aa8` / `FUN_14030a84`) and enters `XBLRamDumpMain` (`0x85e357a8`), which checks `0xb00000` (`0x574f4c44`) and `0xb003f4 == 5` (`FORCE UPLOAD is enabled!`), displays `"[ UPLOAD MODE ]"`, `"DDR Vendor"`, and `"SOC_HW_REVISION"` on the framebuffer (`0x85e69b68`), checks `vol_down_status`, and if enabled writes crash dumps to SD (`/mmc1/ram_dump/`, `boot_sd_ramdump.c` `0x85e42c34`), raw partition (`boot_raw_partition_ramdump.c` `0x85e41b2c`), or Sahara (`sbl1_sahara.c` `0x85e46648`); if debug level is LOW and Force Upload is off, it logs `"@ Continue boot device by Debug level LOW !!"` and resets.

---

## 2. `VerifiedBootDxe.efi` & `TzDxe.efi`

Both drivers are `AArch64` (`0xaa64`) PE32+ DXE drivers with `ImageBase = 0x0` (`VA == RVA == FileOffset`), loaded from `inner_dxe_fv.bin` inside `xbl.elf`.

### 2.1 `VerifiedBootDxe.efi` (`QcomVerifiedBootProtocol`)

- **Container**: `57,344` bytes (`SHA-256: ea66a9126ff41fc53e1e226ef102364c57e8f3483ed413b3cd29cf66d8033e4f`), entry `_ModuleEntryPoint` (`0x1000`) / `entry` (`0x1130`) -> `FUN_0000283c` (`0x283c`).
- **Installed Protocol**: `gGuid_QcomVerifiedBootProtocol` (**`8e5eff91-21b6-47d3-af2b-c15a01e020ec`**, `.data` RVA `0xc0c0`), interface table at **`0xc188`** (`Revision = 0x10002`):

| Vtable Offset | Function RVA | Method Role | Implementation Details |
| --- | --- | --- | --- |
| `+0x00` | `0x10002` | `Revision` | Protocol revision `1.2` |
| `+0x08` | `0x155c` | `VBRwDeviceState` | Reads/writes `devinfo` (`is_unlocked` / device state). Queries `readSecurityState` (`0x398c`); if RPMB-enabled (`(state & 0x47) == 0x40`), locates `QcomQseecomProtocol` (`0xc100`), starts/queries `"keymaster"` (using `QcomTokenSpaceGuid` `882f8c2b-9646-435f-8de5-f208ff80c1bd` @ `0xc050`), and sends Keymaster cmd **`0x202`** (read) / **`0x203`** (write) with a `0x1000`-byte buffer (`0x392c` RPMB check `(state & 0x67) == 0x40`); otherwise falls back to direct BlockIo read/write (`0x28d8` / `0x2a74`) on the `"devinfo"` GPT partition. |
| `+0x10` | `0x1494` | `VBDeviceInit` | Locates `ASN1X509` protocol (`0xc0d0`), stores `is_unlocked` (`DAT_0000c210`), sets `DAT_0000c180 = 1` (`ORANGE`) if unlocked else `0`. |
| `+0x18` | `0x1f98` | `VBSendROT` | Computes SHA-256 Root-of-Trust digest (`0x314c` unlocked / `0x2f40` locked via `EfiHash2Protocol_Qcom` `0xc0b0`), sends Keymaster cmd **`0x201`** (Set ROT) and **`0x200`** (Get Version; if `major > 2`, also sends cmd **`0x208`** `SendBootState` @ `0x1d78`). If secure & non-GREEN, queries TZ feature `10` (`0x3ae8`) and sets fuses `0` (`TZ_HLOS_IMG_TAMPER_FUSE`) and `0x17` (`TZ_HLOS_TAMPER_NOTIFY_FUSE`) via `0x39ec`. |
| `+0x20` | `0x1a64` | `VBSendMilestone` | Sends Keymaster cmd **`0x204`** (`0x40`-byte resp check), checks TZ feature `10` (`0x3ae8` -> `0x3ab4`), blows fuse **`0x16`** (`TZ_HLOS_BL_MILESTONE_FUSE`) via `0x39ec(0x16)`, then calls `QseecomShutdownApp`. |
| `+0x28` | `0x24a0` | `VBVerifyImage` | Computes image + auth_attrs SHA-256 (`0x2c8c`), verifies RSA signature (`0x3670` via `SecRSA` `0xc0e0`) against OEM cert (`0x33e8` -> `GREEN=0`) or embedded key (`0x32f4` -> `YELLOW=2`), else `RED=3`. |
| `+0x30` | `0x1c3c` | `VBDeviceResetState` | Sends Keymaster cmd **`0x10e`** via `QcomQseecomProtocol+0x18`. |
| `+0x38` | `0x23fc` | `VBIsDeviceSecure` | Calls `0x392c` and `0x398c` (`readSecurityState`). |
| `+0x40` | `0x2730` | `VBGetBootState` | Returns cached `DAT_0000c180` (`GREEN=0`, `ORANGE=1`, `YELLOW=2`, `RED=3`). |
| `+0x48` | `0x2798` | `VBGetCertFingerPrint` | Returns SHA-256 of leaf cert (`0x34dc`) when boot state is `YELLOW` (`2`). |

- **SCM Calls in `VerifiedBootDxe.efi`**:
  - `0x3858` (`readSecurityState`): `QcomScmProtocol+0x38` (`ScmSipSysCall`) with `SmcId = 0x2000604`, `ParamId = 0`.
  - `0x39ec` (`set_fuse`): `ScmSipSysCall` with `SmcId =` **`0x2000801`**, `ParamId = 1`, `Parameters[0] = fuse_id` (`0`, `0x16`, `0x17`).
  - `0x3ae8` (`ScmGetFeatureVersion`): `ScmSipSysCall` with `SmcId = 0x2000603`, `ParamId = 1`, `Parameters[0] = feature_id` (`10`).

### 2.2 `TzDxe.efi` (`QcomScmProtocol` & `QcomQseecomProtocol`)

- **Container**: `69,632` bytes (`SHA-256: 799f8fef6dc2c1493d5d4114887e19747b87eb3c499ebe27c5b3f3c36e0aca32`), entry `0x1130`, `FUN_00001494` (`0x1494`) initializes `QcomScmProtocol` (`0x311c`), SSD keystore (`0x2f18`, `SmcId = 0x2000705`, `ParamId = 0x22`), and `QcomQseecomProtocol` (`0x23c4`, `TzeLoaderDxe.c`), then installs exit-boot-services callback (`0x2094`).
- **`QcomScmProtocol` (`77ed108d-8524-4b8b-9d2e-34987aecb9c1` @ `0xf120`)**:
  - `FUN_00005484` (`0x5484`) probes `0x2000601` (`arg = 0x2000602`) to select ARMv8 (`0xf338` vtable, `Revision = 0x10001`) over legacy ARMv7 (`0xf298`), allocating 4 KiB-aligned uncached buffers `DAT_0000f700` (`0x38` B) and `DAT_0000f708` (`0x2000` B) via `UncachedMemoryAllocationLib` (`0x4b40` -> `0x5bc8`).
  - **Vtable (`0xf338`)**: `+0x08/+0x10/+0x18` (`0x4e74`/`0x4e7c`/`0x4e84` stubs returning `EFI_UNSUPPORTED`), `+0x20` (`0x5238` `ScmRegisterCallback`, `SmcId = 0x32000201`, `ParamId = 0x83`, up to 10 callbacks in `0xf530`), `+0x28` (`0x4e8c` `ScmSendCommand` for QSEE OS/app/listener SMCs), `+0x30` (`0x5310` `ScmExitBootServicesHandler`, flushes via `0x32000202`), **`+0x38` (`0x4d28` -> `0x4d40` -> `0x4ba4` -> `0x5604` `ScmSipSysCall`)**.
  - **ARMv8 SMC Calling Convention (`0x4ba4` + `0x5604`)**:
    - ORs `SmcId` with `0x40000000` (AArch64 SMC64 convention), passes `x0 = SmcId | 0x40000000`, `x1 = ParamId`.
    - For `nargs <= 4` (`ParamId & 0xf`), passes args directly in `x2..x5`; for `5..10` args, passes args `0..2` in `x2..x4` and sets `x5 = DAT_0000f700` containing args `3..9`.
    - Executes `smc #0` (`0x562c`), looping while `(int)w0 > 0` (TZ preemption yield).
    - `0x4d40` checks `local_b8 == 1` (TZ listener request), dispatches the registered listener callback (`0xf530`), and resumes TZ with `SmcId = 0x32000203`, `ParamId = 2`.
  - **`ScmSendCommand` (`0x4e8c`) SMC Dispatch**: Maps internal command IDs to QSEE SMCs: `1` -> `0x32000101` (`ParamId=3`, start app), `2` -> `0x32000102` (`ParamId=1`, shutdown app), `3` -> `0x32000103` (`ParamId=0x22`, lookup app by name), `6` -> **`0x30000001`** (`ParamId=0x885`, QSEECom send cmd using uncached shared buffer `DAT_0000f708` split into `[req | rsp]`), `0xb` -> `0x32000105` (load service image), `0xc` -> `0x32000106`, `0xd` -> `0x32000107` (register TZApps region `0x21fc`), `0xe` -> `0x32000401`, `0xf` -> `0x32000402`, `0x10` -> `0x32000403`, and `0xd`/`0xe` log buffer init (`0x22d8` -> `0x459c`).

- **`QcomQseecomProtocol` (`a74862ce-680f-4fe1-a311-df41f4030391` @ `0xf160`)**:
  - Installed at **`0xf248`** (`Revision = 0x10006`): `+0x08` (`0x2708` `QseecomStartApp` — checks if loaded via cmd `3`, appends `"64"` fallback in `0x4830`, reads partition/FV into `0x82000`+ uncached buffer `DAT_0000f400`, sends cmd `1` via `0x471c`), `+0x10` (`0x265c` `QseecomShutdownApp` -> cmd `2`), `+0x18` (`0x25b4` `QseecomSendCmd` -> copies req to `DAT_0000f400`, sends cmd `6` `0x30000001`), `+0x20` (`0x2d84` `QseecomStartAppByGuid`), `+0x28` (`0x4260` `LoadSecureApps` — maps `TzAppsRegnAddr`/`TzAppsRegnSize`, loads `cmnlib`, `cmnlib64`, `keymaster`), `+0x30` (`0x288c`), `+0x38` (`0x2d94`).

---

## 3. Samsung `bksecapp.elf` (`bksecapp.mbn`, `APP_ID = 0x888`)

### 3.1 Container, Entry Points & `0x138`-Byte IPC Struct

[`bksecapp.elf`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_BKSECAPP/bksecapp.elf) (`242,568` bytes, SHA-256 `6539213ec78f8282fd411eb505f0dd4de20b686ab39f2cf2978806f6468b4680`) is a 32-bit `ELFCLASS32` (`EM_ARM`, Thumb-2 + ARM32 SVC trampolines) QSEE TrustZone applet with `8` PHDRs (`0x0` `.text`, `0x1b000` `.data+.bss`, `0x4e000` `.got`, `0x4f000` `.dynamic`, `0x50000` hash/reloc, `0x51000` MBN v5 with `APP_ID = 0000000000000888`, `SW_ID = 000000000000000C`, and `512`-byte `SignerVer02` footer at `0x3b188`). *Note*: Ghidra loaded `bksecapp.elf` at `ImageBase = 0x10000`, so `Ghidra_VA = ELF_VA + 0x10000` (`RVA == ELF_VA`).

- **Lifecycle Entry Points**:
  - **CRT0 (`0x0`, ARM32)**: Checks `r0 == 2 && r1 == 1`, initializes stack, and calls QSEE TA runtime loop `0x83e0`.
  - **`tz_app_init` (`0x7e00` -> `0x4c`)**: Initializes crypto/log state (`0x8890`, `0x886c(0x19)`) and logs `"BKSECAPP Init "`.
  - **`tz_app_cmd_handler` (`0x7d84` -> `0x274`)**: Invoked by QSEE dispatcher (`0x7da8`, expecting `0x24`-byte IPC descriptor).
  - **`tz_app_shutdown` (`0x7e0c` -> `0x4a4`)**: Logs `"BKSECAPP Shutdown"`.
  - **QSEE Syscalls (`0x16030`/`0x16054` ARM32 `svc #0x1400`) & Object Table (`0x9360` / `0x92fc`)**: Resolves QSEE kernel services including `0x17` (shared buffer register/deregister `0xa6c8`/`0xa754`), `0x1c` (QFPROM fuse read/write `0xa640`/`0xa5c4`), `0x34` (secure memory / RPMB-backed SFS/ICCC storage `0xa83c`/`0xa8a8`), and `0x15` (SFS `0xa914`/`0xa9ec`).

- **Request / Response Struct (`0x138` = `312` bytes, matching ABL `0x8994` / `0x1063c`)**:
  - `+0x00` (`uint32_t`): `cmd_id` (validated `req_len >= 4`, then `req_len >= 0x138` & `rsp_len >= 0x138` for standard commands; `0x64/0x65` require `req >= 0x18, rsp >= 8`; `0x66` requires `req >= 0x10, rsp >= 0x138`).
  - `+0x04..+0x133` (`0x130` bytes): Command-specific payload (e.g., `+0x04`: `32`-byte kernel SHA-256 for `cmd 0xc`, or `0xf0`-byte BL ICCC struct for `cmd 0x9`, or `0x34`-byte RoT struct for `cmd 0xa`).
  - `+0x134` (`int32_t`): Return value / status (`0xfffffffd` if `BL_BOOT_COMPLETE` lock is active for any `cmd != 0x65`; `0xfffffffe` if buffer too small; `0xfffffff7` if unsupported).

### 3.2 Complete `bksecapp` Command Dispatch Table (`0x274`)

| `cmd_id` | Handler RVA (Ghidra VA) | ABL Caller (`LL` / `Odin`) | QFPROM / Secure Mem / Action & Return Value |
| --- | --- | --- | --- |
| **`0x0`** | `0x08f0` (`0x108f0`) | `tima_get_warranty_vio_fuse` (`0x8b70` / `0x10818`) | Reads QFPROM **`0x7805b0`**; returns `lsb & 1` (`0` = intact, `1` = Knox Warranty Void, `-1` on read error). |
| **`0x1`** | `0x0860` (`0x10860`) | `tima_set_warranty_vio_fuse` (`0x8c38` / `0x108e0`) | Blows QFPROM **`0x7805b0`** with `{lsb=1, msb=0}` via `0xa5c4`; returns `0` on success, `-1` on write error. |
| **`0x7`** | `0x0c60` (`0x10c60`) | `get_anti_rollback_en` (`0x9154` / `0x10c2c`) | Reads QFPROM **`0x780198`**; returns `msb & 0xf` (`anti_en`, `0` = RP disabled, non-zero = RP enabled). |
| **`0x8`** | `0x0d04` (`0x10d04`) | `get_anti_rollback_ignore` (`0x9234` / `0x10d0c`) | Calls `0xc60` (`cmd 0x7`) and reads QFPROM **`0x780158`**; returns `1` (`TEST DEVICE`) if `anti_en == 0 && (lsb & 0x100420) == 0x100420`, else `0` (`-1` on error). |
| **`0x9`** | `0x006c` (`0x1006c`) | `iccc_write_bl_data` (`0x9ec0`) | `tzbsp_oem_write_iccc_bl_info`: calls `Iccc_InitData_TA(0xff)` (`0x2c7c`, clears secure mem `0x800..0xe50`), saves `0xff100000 = 0`, checks `*(short*)(payload+2) == 0xf0`, saves `0xfff000ff` (`0xf0` B to offset `0x800`). |
| **`0xa`** | `0x013c` (`0x1013c`) | `iccc_write_bl_data` (`0x9ec0`) | `tzbsp_oem_write_iccc_rot_bl_info`: checks `*(short*)(payload+2) == 0x34`, saves `0xff3000ff` (`0x34` B RoT data to offset `0xd00`). |
| **`0xb`** | `0x0794` (`0x10794`) | `is_secboot_enable` (`0x8d04` / `0x109ac`) | Returns 4-bit Qualcomm Secure Boot mask (`0xf` = `ENABLE`, `0x0` = `NONE`): **bit 0** (`0x69c`): `CHECK_OEM_PK_HASH` compares QFPROM **`0x7801c8, 0x7801d0, 0x7801d8, 0x7801e0`** against Samsung OEM PK hash table at `0x1b020`; **bit 1** (`0x4b8`): `CHECK_SEC_BOOT` QFPROM **`0x780350`** (`lsb == 0x303030`); **bit 2** (`0x554`): `CHECK_OEM_CONFIG` QFPROM **`0x780188`** (`((~msb & 0x7beff5fd) \| (~lsb & 0xc0000000)) == 0`); **bit 3** (`0x600`): `CHECK_RW_PERM` QFPROM **`0x780158`** (`(lsb & 0x1000) != 0`). |
| **`0xc`** | `0x0aec` (`0x10aec`) | `measure_kernel` (`0x8dc8`) | **TIMA Trusted Boot**: registers/maps physical **`0x9f800000`** (`0x200` B, populated by `XBL_Loader` `0x14036ee4`) via `0x99c`, verifies `count == 6` (`1..7` valid), appends 32-byte kernel SHA-256 (`payload[0..3]`), increments count to `7`, writes `0x200` B to secure mem **`0x400`**, and clears golden msr at secure mem **`0x600`** via `0xa8a8`. |
| **`0xd`**, `0x14`, `0x16` | `0x0db0` (`0x10db0`) | `get_anti_rollback_xbl_ver` (`0x9300` / `0x10dd8`) | **RP SWREV XBL**: reads QFPROM **`0x780168`**, returns `popcount(lsb) + popcount(msb)` (64 bits). |
| **`0xe`** | `0x0e6c` (`0x10e6c`) | `get_anti_rollback_pil_ver` (`0x93e0` / `0x10eb8`) | **RP SWREV PIL/Modem**: reads QFPROM **`0x780170`** (`popcount(lsb)`, 32 bits) + QFPROM **`0x780178`** (`popcount((lsb >> 8) & 0xffff)`, 16 bits). |
| **`0xf`** | `0x1030` (`0x11030`) | `get_anti_rollback_rpm_ver` (`0x94c0` / `0x10f98`) | **RP SWREV RPM**: reads QFPROM **`0x780170`**, returns `popcount((msb >> 17) & 0xff)` (8 bits). |
| **`0x10`** | `0x0f84` (`0x10f84`) | `get_anti_rollback_tz_ver` (`0x95a0` / `0x11078`) | **RP SWREV TZ**: reads QFPROM **`0x780170`**, returns `popcount(msb & 0x1ffff)` (17 bits). |
| **`0x11`** | `0x10dc` (`0x110dc`) | `get_anti_rollback_hyp_ver` (`0x9680` / `0x11158`) | **RP SWREV HYP**: reads QFPROM **`0x780178`**, returns `popcount(msb & 0xfff)` (12 bits). |
| **`0x12`** | `0x1188` (`0x11188`) | `get_anti_rollback_dp_ver` (`0x9760` / `0x11238`) | **RP SWREV DP (`apdp`/AP)**: reads QFPROM **`0x780178`**, returns `popcount((msb >> 12) & 0x1f)` (5 bits). |
| **`0x13`** | `0x1234` (`0x11234`) | `get_anti_rollback_dev_cfg_ver` (`0x982c` / `0x11304`) | **RP SWREV DevCfg**: reads QFPROM **`0x780178`**, returns `popcount((msb >> 17) & 0x7ff)` (11 bits). *(Note: `K` & `S` in Odin's `RP SWREV : B%d(%d,%d,%d,%d,%d) K%d S%d` come from `Odin.efi` `0x14f90` / `0x14fcc`, both returning `7`.)* |
| **`0x15`** | `0x12e0` (`0x112e0`) | `get_rpmb_fuse` (`0x990c` / `0x113e4`) | Reads QFPROM **`0x780178`**, returns `(lsb >> 24) & 1` (RPMB provision/key fuse bit). |
| **`0x18`** | `0x162c` (`0x1162c`) | `get_ek_fuse` (`0x8f98` / `0x10a70`) | Reads QFPROM **`0x7805b0`**, returns `(lsb >> 8) & 0x3` (2-bit Engineering/Knox fuse `[9:8]`). |
| **`0x19`** | `0x157c(1)` (`0x1157c`) | `set_ek_fuse` (`0x9064` / `0x10b3c`) | Blows QFPROM **`0x7805b0`** with `0x100` (`1 << 8`). |
| **`0x1a`** | `0x157c(3)` (`0x1157c`) | `set_ek_fuse` (`0x9064` / `0x10b3c`) | Blows QFPROM **`0x7805b0`** with `0x300` (`3 << 8`). |
| **`0x1b`** | `0x157c(2)` (`0x1157c`) | `set_ek_fuse` (`0x9064` / `0x10b3c`) | Checks `get_ek_fuse() == 1`; if so, blows QFPROM **`0x7805b0`** with `0x200` (`2 << 8`). |
| **`0x1c`** | `0x1808` (`0x11808`) | `set_bl_boot_complete` (`0x99d8`) | Writes `1` to secure mem **`0xe50`** (`process_bl_boot_complete`), locking out all `bksecapp` commands except `0x65`. |
| **`0x64` (`100`)** | `0x13dc` (`0x113dc`) | `dmv_write_bl_data` (`0xa184`) | Writes DM-Verity / verified-boot status (`case 1..3`) to secure mem `0x4`/`0x8`/`0xc` (`case 3` ORs `0x5afe0000`). |
| **`0x65` (`101`)** | `0x1474` (`0x11474`) | — | Reads `0x14`-byte DM-Verity status block from secure mem `0x0` (only command permitted after `0x1c`). |
| **`0x66` (`102`)** | `0x1508` (`0x11508`) | `kaslr_write_bl_data` (`0xa098`) | Writes `0xc`-byte KASLR seed/offset flags to secure mem **`0x14`**. |
