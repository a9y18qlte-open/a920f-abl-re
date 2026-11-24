# Kernel Boot, DTB/DTBO Matching, and Kernel Command Line (`LinuxLoader.efi`)

**Target**: Samsung Galaxy A9 (2018) `SM-A920F` (`a9y18qlte`, Qualcomm SDM660)  
**Binary**: `extracted/F/LinuxLoader.efi` (AArch64 PE32+, `ImageBase = 0x0`, `EntryPoint = 0x1000`, `1,490,944` bytes; `VA == RVA == FileOffset`)  
**Verification Script**: [`scripts/analyze_dtb_cmdline.py`](../scripts/analyze_dtb_cmdline.py)

---

## 1. `boot.img` / `recovery.img` Parsing & Kernel Handoff

### 1.1 High-Level Boot Execution Chain

1. `_ModuleEntryPoint` (`0x1000`) -> `FUN_00001574` (`0x1574`) -> `LinuxLoaderEntry` (`FUN_00001794`, `0x1794`).
2. `LinuxLoaderEntry` initializes board hardware (`FUN_00016740`), multi-slot check (`FUN_00027618(L"boot")`), `bksecapp` (`FUN_00008860`), BCB/recovery detection (`FUN_00026e1c`), and calls:
   - `0x1eec`: `LoadImageAndAuth` (`FUN_00002154`) — loads `boot`/`recovery` and `dtbo` raw partitions into memory. On error (`x0 != 0`), branches via `0x1f28: b #0x1b34` to **Download Mode** (`Odin.efi`).
   - `0x1f64`: `Sec_Auth_Kernel.c` (`FUN_00006ba4`) — verifies Samsung `SignerVer02` / RSA signature on `boot`/`recovery` **only** (never `dtbo`), runs TIMA measurement (`FUN_00008dc8`), and subtracts `0x210` bytes (`SignerVer02` / `SEANDROIDENFORCE` trailer) from `ImageSize`. On auth error, calls `FUN_000080c8` (Warranty Bit / Download Mode / power-off).
   - `0x2148`: `BootLinux` (`FUN_0001db2c`) — parses image header, decompresses kernel, selects DTB / applies DTBO, builds kernel `cmdline`, updates FDT, shuts down UEFI boot services, and jumps to the Linux kernel.
   - `0x214c`: `b #0x1b34` — **any return** from `BootLinux` unconditionally falls through into **Download Mode** (`"Launching Download Mode\n"` -> loads `fs0:Odin`..`fs9:Odin` via `FUN_0002549c`).

### 1.2 Boot Image Header Parsing & Versions (v0 / v1 / v2)

`LoadImageAndAuth` (`FUN_00002154`) allocates a `0x460`-byte `BootInfo` context (`param_1`) and loads the target partition via `FUN_0001f318` (`0x1f318`), which reads one block/page (default `0x1000` via `FUN_0001ca88`) and validates the header in `FUN_0001ee3c` (`0x1ee3c`):

| Header Field | Offset | Validation / Handling (`FUN_0001ee3c` & `BootLinux` `0x1db2c`) |
|---|---|---|
| `magic[8]` | `+0x00` | Must equal `"ANDROID!"` (8 bytes). |
| `kernel_size` | `+0x08` | Must be `!= 0` (`"Invalid kernel size\n"`). |
| `ramdisk_size` | `+0x10` | Page-aligned up by `page_size`. |
| `second_size` | `+0x18` | Read in `BootLinux` (`[sp, #0x10]`) for `recovery_dtbo` offset calculation (`0x2a880..0x2a8c8`). Note: `FUN_0001ee3c` omits `second_size` from `ImgSizeActual = PageSize + KernelActual + RamdiskActual`. |
| `page_size` | `+0x24` | Must be `!= 0`; rejects `(page_size != block_size) && (page_size > 0x1000)` (`"Invalid image pagesize\n"`). |
| `header_version` (or legacy `dt_size`) | `+0x28` | Printed as `"Image Header version     : 0x%x\n"` and stored into `BootInfo + 0x458` at `0x1e480`. |
| `cmdline[512]` | `+0x40..+0x23f` | Copied as `BootInfo` cmdline; forced NUL-terminated at `[+0x23f]`. |
| `recovery_dtbo_size` | `+0x660` | v1+ recovery header only: 32-bit size validated in `FUN_0002a788` (`0x2a788`). |
| `recovery_dtbo_offset` | `+0x664` | v1+ recovery header only: 64-bit offset checked against `ImageSize` in `FUN_0002a788`. |
| `header_size` | `+0x66c` | When `header_version == 1`, `FUN_0002a788` enforces `*(uint32_t*)(hdr + 0x66c) == 0x670`. |

After `FUN_0001ee3c` returns the payload size, `FUN_0001f318` adds `0x210` bytes (`*param_3 + 0x210`) for the Samsung signature trailer, page-aligns up, allocates pages, and reads the full partition via `FUN_000251bc`.

### 1.3 Gzip Decompression & Uncompressed Kernel Formats

Inside `BootLinux` (`FUN_0001db2c`), the kernel payload starting at `BootImgBuf + PageSize` (`[sp, #0x60] + [sp, #8]`) is inspected:

1. **Patched `"UNCOMPRESSED_IMG"` header (`0x1dfc0..`)**: If the first 16 bytes equal `"UNCOMPRESSED_IMG"`, `BootLinux` reads a 4-byte DTB offset at `+0x10` and skips a `0x14`-byte prefix.
2. **Gzip detection (`FUN_0001fa38`, `0x1fa38`)**: Returns `TRUE` when `KernelSize > 9` and bytes `[0..2]` are `0x1f, 0x8b, 0x08`.
3. **Zlib decompression (`FUN_0001f6e0`, `0x1f6e0`)**:
   - Uses embedded zlib `1.2.8` (`inflateInit2` at `0x331cc`, `inflate` at `0x332a8`, `inflateEnd` at `0x34a7c`).
   - Decompresses the gzip stream (`Image.gz`) directly to `KernelLoadAddr`, tracks `z_stream.next_in` to return the exact compressed gzip stream length (`local_10c` at `[sp, #0x84]`) plus decompressed size (`[sp, #0x88]`).
   - That compressed stream byte length locates the **appended DTB** immediately following `Image.gz` (`Image.gz-dtb` layout): `DtbOffset = KernelBuf + local_10c`.
4. **AArch64 vs ARM32 Image Detection (`0x1dff0..0x1dff4`)**:
   - Checks offset `+0x38` of the decompressed kernel (`ldr w0, [x22, #0x38]; cmp w0, w24`) against `0x644d5241` (`"ARMd"`, little-endian ARM64 `Image` magic). If matched, selects 64-bit load address and 64-bit entry path; otherwise uses 32-bit load address and 32-bit entry path.

### 1.4 Physical Memory Map & Load Addresses

`BootLinux` obtains DDR `MemoryBase` via `FUN_0001c424` (`0x1c424`), which reads UEFI RAM partitions (`0x80000000`, matching `extracted/xbl_uefiplat.cfg` `"Kernel"` region starting at `0x80000000`):

| Artifact | Base Offset (`MemoryBase = 0x80000000`) | Resolved Physical Address | Source Constant / RVA |
|---|---|---|---|
| **Kernel (64-bit)** | `MemoryBase \| 0x80000` + KASLR slide | `0x80080000` + `((rand32 & 0x3f) << 14)` | `0x1e0cc`: `ubfiz w23, w10, #0xe, #6` |
| **Kernel (32-bit)** | `MemoryBase \| 0x8000` | `0x80008000` | `0x75a44` (`0x00008000`) |
| **Device Tree (FDT)** | `MemoryBase \| 0x5400000` | `0x85400000` | `0x75a38` (`0x05400000`) |
| **Ramdisk** | `MemoryBase \| 0x21c00000` | `0xa1c00000` (end must be `< 0xb0000000`) | `0x75a3c` (`0x21c00000`), `0x75a40` (`0x30000000`) |

**KASLR Slide (`0x1e044..0x1e0e0`)**: Calls `FUN_0001d9f4` (`0x1d9f4`, RNG) for a 32-bit random word, computes `slide = (rand32 & 0x3f) << 14` (0..63 * 16 KiB, max `0xfc000`), adds it to `KernelLoadAddr`, writes magic `0xcdefcdef` and `slide` (`stp w0, w23, [x16]`) to `0x9fa07000` / `0x9fa07004` (`0x1e0dc`), and notifies TrustZone via SCM call `FUN_0000a098` (`0x1e0e0`).

### 1.5 Pre-Handoff Shutdown & Exact Kernel Entry Register State

Before branching to the kernel (`0x1eb74..0x1ed14`), `BootLinux` performs:
1. `0x1eb74`: `FUN_0006f444` (`0x6f444`) — configures UFS/eMMC write protection (`[BL WP]`, `[SYS WP]`).
2. `0x1eb78`: `FUN_000099d8` (`0x99d8`) — `bl_boot_complete` TZ milestone.
3. `0x1ebec`: `ShutdownUefiBootServices` (`FUN_0001bce0`, `0x1bce0`) — calls `gBS->GetMemoryMap` and `gBS->ExitBootServices`.
4. `0x1ebf8`: `FUN_0001be28` (`0x1be28`) — shuts down ARM arch timer, GIC, data/instruction caches, and MMU.

Then `BootLinux` jumps to the kernel entry point (`x18` for 64-bit, `x25` for 32-bit):

- **AArch64 64-bit Kernel Entry (`0x1ecc0..0x1ecd0`)**:
  ```asm
  0x1ecc0: ldp x0, x18, [sp, #0x20]   ; x0 = DeviceTreeLoadAddr (0x85400000), x18 = KernelLoadAddr
  0x1ecc4: ldr x1, [sp, #0x18]        ; x1 = MemoryBase (0x80000000)
  0x1ecc8: mov x3, xzr                ; x3 = 0
  0x1eccc: sub x2, x18, x1            ; x2 = KernelLoadAddr - MemoryBase (0x80000 + kaslr_slide)
  0x1ecd0: blr x18                    ; jump to kernel
  ```
  *Note*: Unlike upstream ARM64 Linux boot protocol (`x1 = x2 = x3 = 0`), Qualcomm/Samsung ABL intentionally passes `x1 = MemoryBase` and `x2 = kernel_offset_from_ram_base`.
- **ARM32 32-bit Kernel Entry (`0x1ecd8..0x1ece4`)**:
  ```asm
  0x1ecd8: ldr x2, [sp, #0x20]        ; r2 = DeviceTreeLoadAddr (FDT)
  0x1ecdc: mov w0, wzr                ; r0 = 0
  0x1ece0: mov w1, wzr                ; r1 = 0
  0x1ece4: blr x25                    ; jump to 32-bit kernel
  ```

---

## 2. Appended DTB / DTBO Matching Algorithm

`LinuxLoader.efi` contains **two distinct DTB matching pipelines**:
1. **Legacy appended DTB matcher** (`FUN_0001fb3c` at `0x1fb3c`), used when no valid DTBO header is present (`FUN_0002a788` returns `0`).
2. **DTBO-era DTB + DTBO matcher** (`FUN_00021624` + `FUN_00021888` + `FUN_000226c4`), used when `FUN_0002a788` returns `1`.

### 2.1 `FUN_0001fb3c` — Appended DTB Matching (`0x1fb3c`)

1. Walks every concatenated FDT starting from `KernelBuf + CompressedKernelSize` (checking FDT magic `0xd00dfeed` via `fdt32_to_cpu` `0x2f450` and header/size bounds).
2. Extracts four root properties from each FDT:
   - `"model"`
   - `"qcom,msm-id"` — tuples of `2 * uint32` (`<soc_id, soc_rev>`)
   - `"qcom,board-id"` — tuples of `2 * uint32` (`<board_variant_major_minor, platform_subtype_hwrev>`)
   - `"qcom,pmic-id"` — tuples of `4 * uint32` (`<pmic0, pmic1, pmic2, pmic3>`)
3. Expands the Cartesian product of `(msm-id, board-id, pmic-id)` into `0x30`-byte candidate entries, checking Samsung's hardware revision against `FUN_000167f4()` (`0x167f4`): a candidate DTB's `hw_rev` byte must satisfy `board_hw_rev >= dtb_hw_rev` (`0x1fb3c` line 895).
4. Filters and ranks surviving candidates in strict tie-breaker order:
   - `FUN_00022938(..., 0)` (`0x22938`): matches SoC **Foundry ID** (`BoardInfo` via `0x1cdec`).
   - `FUN_00022b5c(..., 1)` (`0x22b5c`): matches **SoC Revision** (`soc_rev` exact, else highest `<` board).
   - `FUN_00022b5c(..., 2)`: matches **`qcom,board-id` Major/Minor version** (`& 0xff0000`, `& 0xff00` exact, else highest `<=` board).
   - `FUN_00022b5c(..., 3)`: matches **Samsung `hw_rev`** (`FUN_000167f4()`, exact match preferred, else highest `<=` board revision).

### 2.2 `FUN_00021888` — `DtbInfo` Struct & `DtMatchVal` Bitmask (`0x21888`)

Both `FUN_00021624` (SoC base DTB lookup, `mode = 0x1c`) and `FUN_000226c4` (DTBO entry lookup, `mode = 0x1b`) score blobs using `FUN_00021888`, which builds a `0x48`-byte `DtbInfo` structure:

| Offset | Size | Field | Source / Mask |
|---|---|---|---|
| `+0x00` | 4 | `soc_id` | `qcom,msm-id[0] & 0xffff` |
| `+0x04` | 4 | `soc_rev` | `qcom,msm-id[1]` |
| `+0x08` | 4 | `foundry_id` | `(qcom,msm-id[0] >> 16) & 0xff` |
| `+0x0c` | 4 | `board_variant` | `qcom,board-id[0] & 0xff` |
| `+0x10` | 4 | `plat_ver_major` | `qcom,board-id[0] & 0xff0000` |
| `+0x14` | 4 | `plat_ver_minor` | `qcom,board-id[0] & 0xff00` |
| `+0x18` | 4 | `subtype` | `qcom,board-id[1]` |
| `+0x1c..+0x28` | 4×4 | `pmic_model[0..3]` | `qcom,pmic-id[0..3] & 0xff` |
| `+0x2c..+0x38` | 4×4 | `pmic_rev[0..3]` | `qcom,pmic-id[0..3] & 0xffffff00` |
| `+0x3c` | 4 | `DtMatchVal` | 29-bit score bitmask (higher value = better match; `1` = mismatch) |
| `+0x40` | 8 | `dtb_ptr` | Pointer to FDT blob |

Exact `DtMatchVal` bit assignment in `FUN_00021888`:

| Bit(s) | Mask | Meaning |
|---|---|---|
| Bit 28 | `0x10000000` | `qcom,msm-id` SoC ID exact match (`& 0xffff`) |
| Bit 27 | `0x08000000` | `qcom,board-id` variant exact match (`& 0xff`) |
| Bit 26 / 25 | `0x04000000` / `0x02000000` | `subtype` exact match / wildcard (`0`) |
| Bits 24 / 23 | `0x01000000` / `0x00800000` | PMIC[3] model exact match / wildcard (`0`) |
| Bits 22 / 21 | `0x00400000` / `0x00200000` | PMIC[2] model exact match / wildcard (`0`) |
| Bits 20 / 19 | `0x00100000` / `0x00080000` | PMIC[1] model exact match / wildcard (`0`) |
| Bits 18 / 17 | `0x00040000` / `0x00020000` | PMIC[0] model exact match / wildcard (`0`) |
| Bits 16 / 15 | `0x00010000` / `0x00008000` | Foundry ID exact match / wildcard (`0`) |
| Bits 14 / 13 | `0x00004000` / `0x00002000` | `soc_rev` exact match / DTB `<` board |
| Bits 12 / 11 | `0x00001000` / `0x00000800` | `plat_ver_major` exact match / DTB `<` board |
| Bits 10 / 9 | `0x00000400` / `0x00000200` | `plat_ver_minor` exact match / DTB `<` board |
| Bits 8 / 7 | `0x00000100` / `0x00000080` | PMIC[3] rev exact match / DTB `<` board |
| Bits 6 / 5 | `0x00000040` / `0x00000020` | PMIC[2] rev exact match / DTB `<` board |
| Bits 4 / 3 | `0x00000010` / `0x00000008` | PMIC[1] rev exact match / DTB `<` board |
| Bits 2 / 1 | `0x00000004` / `0x00000002` | PMIC[0] rev exact match / DTB `<` board |
| Bit 0 | `0x00000001` | Hard mismatch (`DtMatchVal = 1`) |

- **`FUN_00021624` (`mode = 0x1c`)**: Scans appended DTBs in `boot.img`; sets `DAT_0015d018 = 1` (`"Exact DTB match found. DTBO search is not required\n"`) **only if** `(0x1c150000 & ~DtMatchVal) == 0` (`0x216b8`, `0x2170c`) — i.e., **all 6** exact-match bits (SoC ID `0x10000000`, Variant `0x08000000`, Subtype `0x04000000`, PMIC1 `0x00100000`, PMIC0 `0x00040000`, Foundry `0x00010000`) are set simultaneously.
- **`FUN_000226c4` (`mode = 0x1b`)**: Iterates `dtbo` table entries (`dt_entry_count`), validates each FDT, scores via `FUN_00021888(..., 0x1b)` (requiring bit 27 Board Variant exact match), selects the highest `DtMatchVal`, and stores the winning index in `DAT_00156dcc` (returned by `FUN_0001fab4()` for `androidboot.dtbo_idx=`).

---

## 3. `dtbo` Loading, Overlay & SM-A920F Brick Root Cause

### 3.1 `dtbo` Partition Read (`LoadImageAndAuth`, `FUN_00002154`)

1. At `0x23f0..0x2400`, `LoadImageAndAuth` hardcodes `BootInfo + 0x438 = 3` (`AVB version 3` = `NO_AVB`).
2. `NoAVBLoadDtboImage` (`0x26e4..0x2cf8`):
   - Constructs `L"dtbo"` (`+ slot_suffix` if multi-slot).
   - `0x2934`: Calls `FUN_00027ef0(L"dtbo")`. If not found (`-1`), logs `"No dtbo partition is found, Skip dtbo\n"` and continues without `dtbo`. (SM-A920F GPT has a `dtbo` partition, so this succeeds.)
   - `0x2940..0x298c`: Builds `AvbOps` (`FUN_0000452c`, `+0x50 = &LAB_00004440` `get_size_of_partition`) and reads `dtbo` partition byte size into `local_108`.
   - `0x29a0..0x29ac`: Checks `1 <= dtbo_size <= 0x1800000` (24 MiB).
   - `0x29dc..0x29f8`: Allocates `BootInfo + 0x148` and calls `FUN_000251bc` (`LoadImageFromPartition`) to read the entire raw `dtbo` partition into RAM, setting `BootInfo[0x428] = 2`.
   - **No cryptographic verification is performed on `dtbo`**: AVB is `NO_AVB` (`3`), and `Sec_Auth_Kernel` (`0x6ba4`) only verifies `boot`/`recovery`.

### 3.2 `ValidateDtbo` (`FUN_0002a788`) Validation Rules

Inside `BootLinux` (`0x1e484`), `FUN_0002a788(BootInfo, &dtbo_buf)` validates the `dtbo` buffer (or `recovery_dtbo` inside `recovery.img` when `BootIntoRecovery != 0` and `HeaderVersion != 0`):
- Converts big-endian `dt_table_header` fields via `fdt32_to_cpu` (`0x2f450`):
  - `0x2aa8c..0x2aaa0`: `magic == 0xd7b7ab1e` (`mov w19, #0xab1e; movk w19, #0xd7b7, lsl #16; bl #0x2f450; cmp w0, w19; b.ne #0x2ab18`).
  - `0x2aaa4..0x2aab4`: `dtbo_img_size < 0x1800001` (`<= 24 MiB`).
  - `0 < total_size <= 0x1800000`
  - `header_size == 0x20`
  - `dt_entry_size == 0x20`
  - `dt_entries_offset <= 0x1800000`
  - `dt_entry_count * dt_entry_size <= dtbo_img_size` and `dt_entries_offset + dt_entry_count * dt_entry_size <= dtbo_img_size`.
- Returns `0` (`FALSE`) if `magic != 0xd7b7ab1e` or any header field fails validation.
- Returns `1` (`TRUE`) if all header checks pass.

### 3.3 Exact RVA-by-RVA Root Cause: Why All-Zero `dtbo` Boots Cleanly, While Writing a `dtbo.img` Bricks to Download Mode

```text
BootLinux (0x1db2c)
  ├─ 0x1e484: bl FUN_0002a788 (ValidateDtbo)
  ├─ 0x1e4a8: cbz w5, 0x1e62c
  │
  ├──[w5 == 0: dtbo is all-zeros (0x0 != 0xd7b7ab1e) OR invalid magic]──> 0x1e62c
  │     └─ 0x1e62c: bl FUN_0001fb3c   (Appended DTB matching with Samsung hw_rev)
  │        └─ Matches stock appended DTB -> Boots Linux cleanly!
  │
  └──[w5 == 1: dtbo has valid dt_table_header magic 0xd7b7ab1e]──────────> 0x1e4ac
        ├─ Gate A (0x1e4ac): bl FUN_00021624(mode=0x1c)
        │    └─ If NULL -> 0x1e6b0 ("Error: Appended Soc Device Tree blob not found")
        │       -> BootLinux returns error -> 0x2148 -> 0x214c: b 0x1b34 (Download Mode!)
        │
        ├─ Gate B (0x1e4b8): bl FUN_0001faf4()  [checks DAT_0015d018 == 1]
        │    ├─ Requires ALL 6 bits of 0x1c150000 in FUN_00021624 (0x216b8, 0x2170c);
        │    │  if any field (e.g. subtype or pmic1 or foundry) is 0/wildcard, returns 1.
        │    └─ When == 1: 0x1e4d0: bl FUN_000226c4(mode=0x1b)
        │         └─ If no dtbo entry matches SDM660/variant -> 0x1e7f0
        │            ("Error: Board Dtbo blob not found") -> 0x2148 -> 0x214c (Download Mode!)
        │
        └─ Gate C (0x1e4f4 -> 0x1e528): bl ufdt_install_blob -> bl ufdt_apply_overlay (0x38924)
             └─ ufdt_apply_overlay requires /__symbols__ in base DTB ("Bad main_symbols...").
                Stock a9y18qlte kernels ship standalone appended DTBs without /__symbols__!
                -> If overlay fails: 0x1e98c ("ufdt apply overlay failed")
                   -> BootLinux returns error -> 0x2148 -> 0x214c: b 0x1b34 (Download Mode!)
```

**Summary of the SM-A920F `dtbo` Trap**:
1. **Stock state (all-zeros `dtbo`)**: `LoadImageAndAuth` reads the raw zeroed partition (`NoAVBLoadDtboImage`), `FUN_0002a788` sees `0x00000000 != 0xd7b7ab1e` at `0x2aa9c`, returns `0`, and `0x1e4a8` branches to `0x1e62c` (`FUN_0001fb3c`) — bypassing DTBO completely and booting the appended DTB cleanly.
2. **Non-DTBO payload written to `dtbo`**: If a random/non-DTBO image (`magic != 0xd7b7ab1e`) is written directly (e.g., via `dd` or custom recovery), `FUN_0002a788` still returns `0` (`0x2aaa0 -> 0x2ab18`) and `LinuxLoader.efi` still falls back to `0x1e62c`. *(Note: during Odin flashing, `decomp/F_Odin` performs `SecAuthRet` / `SignerVer01`/`SignerVer02` checks when secure download checks apply, which rejects unsigned Odin downloads.)*
3. **Any valid `dt_table_header` (`0xd7b7ab1e`) written to `dtbo`**: As soon as `magic == 0xd7b7ab1e` and the header passes `0x2a788`, `0x1e4a8` **refuses to run `FUN_0001fb3c`** and enters the DTBO overlay pipeline (`0x1e4ac..0x1e530`). Unless *all* of: (i) the appended DTB passes `FUN_00021624` (`0x1c`), (ii) either `(0x1c150000 & ~DtMatchVal) == 0` OR a `dtbo` entry passes `FUN_000226c4` (`0x1b`), **and** (iii) the base DTB contains `/__symbols__` for `ufdt_apply_overlay` (`0x38924`) to succeed, `BootLinux` returns `EFI_NOT_FOUND` (`0x800000000000000e`), hitting `0x214c: b #0x1b34` in `LinuxLoaderEntry` — **unconditionally forcing the device into Download Mode (`Odin.efi`)**.

### 3.4 Working `dtbo` Configuration (Hardware-Verified)

Even after compiling the base DTB with `DTC_FLAGS += -@` (to emit `/__symbols__`), a stock `a9y18qlte` DTB **still fails Gate A (`FUN_00021624`)** because of `qcom,board-id` cell 1:
- Stock `sdm660-sec-a9y18qlte-eur-r06.dts` sets `qcom,board-id = <0x8 0x6>` (encoding Samsung `hw_rev = 6` in cell 1).
- `FUN_0001fb3c` (non-DTBO path) checks `board_hw_rev >= dtb_hw_rev`, so `0x6` works.
- `FUN_00021888` (`0x21888`, DTBO path `mode = 0x1c`/`0x1b`) only reads the **first** `qcom,board-id` tuple and treats cell 1 as Qualcomm `BoardSubtype` (`FUN_0001d958()`, which is `0` on `SM-A920F`). Any non-zero mismatch (`6 != 0`) triggers `"subtype-id doesnot match"` (`DtMatchVal = 1`).

**Dual-DTB + Overlay Setup (verified on `SM-A920F` for both `boot` and `HeaderVersion == 0` `recovery`):**
1. **Base `Image.gz-dtb`**: Build DTBs with `DTC_FLAGS += -@`, keep the unmodified `<0x8 0x6>` DTB, and append a second copy patched via `fdtput -t x <dtb> / qcom,board-id 0x8 0x0`:
   - When `dtbo` is all-zeros, `FUN_0001fb3c` selects `<0x8 0x6>`.
   - When `dtbo` is active, `FUN_00021624` skips `<0x8 0x6>`, selects `<0x8 0x0>`, and passes it to `ufdt_apply_overlay`.
2. **Overlay `.dts` (`dtc -@`)**:
   - Root `/` specifies `/plugin/;`, `qcom,msm-id = <0x13d 0x0>;`, and `qcom,board-id = <0x8 0x0>;`.
   - Fragments target a label present in `/__symbols__` that also has a `phandle` in the base DTB (e.g., `&soc`, since `/reserved-memory` on `a9y18qlte` lacks a `phandle`), generating `/__fixups__`.
3. **Container (`mkdtboimg` v0)**: 32-byte big-endian `dt_table_header` (`magic = 0xd7b7ab1e`, `header_size = 0x20`, `dt_entry_size = 0x20`, `dt_entry_count = 1`, `dt_entries_offset = 0x20`, `page_size = 2048`, `version = 0`) + 32-byte `dt_table_entry` (`dt_offset = 0x40`) + compiled `.dtbo`.

On `SM-A920F` (`4.19.325` + OrangeFox `recovery.img` repacked with the same dual-DTB kernel), flashing this `dtbo.img` to `sda19` boots cleanly into both Android and OrangeFox with `androidboot.dtbo_idx=0` in `/proc/cmdline` and overlaid properties present under `/sys/firmware/devicetree/base/`.

---

## 4. Complete Kernel `cmdline` Reference

### 4.1 Construction Pipeline

`BootLinux` (`0x1e650`) calls `UpdateCmdLine` (`FUN_000260b4`, `0x260b4`), which:
1. Starts with the `boot.img` header `cmdline` (`+0x40..+0x23f`) and `VBCmdLine` (`BootInfo + 0x440`).
2. Appends `root=` (`FUN_00025d54`), Qualcomm boot/hardware/panel/DTBO parameters (`0x260b4`).
3. Calls Samsung's `sec_update_cmdline` (`FUN_000706bc`, `0x706bc`, `0x800`-byte buffer) to append Samsung debug, `param` offsets, AVB/warranty, DRAM, and board flags (`0x26ba0` / end of `UpdateCmdLine`).
4. Writes the final string to `/chosen/bootargs` in the FDT via `FUN_000241a0` (`0x241a0`).

### 4.2 `GetSystemPath` (`FUN_00025d54`) & Qualcomm `UpdateCmdLine` (`FUN_000260b4`)

| Parameter / Format | Call / Str RVA | Data Source | Condition |
|---|---|---|---|
| `<boot.img cmdline>` | `0x268e4` (`AsciiStrCpy`) | `BootImgHdr + 0x40` (`0x200` bytes max) | When header `cmdline` is non-empty (`w5 != 0`). |
| `<VBCmdLine>` | `0x26904` (`AsciiStrCat`) | `BootInfo + 0x440` (empty in `NO_AVB` mode) | When `VBCmdLine != NULL`. |
| ` root=/dev/mmcblk0p%d` | `0x25ff4` (`0x7fead`) | Partition index via `FUN_00027be0` / `FUN_00027c2c` | eMMC boot device, non-recovery boot (`FUN_0001f628() == 0`). |
| ` rootfstype=ubifs rootflags=bulk_read root=ubi0:rootfs ubi.mtd=%d` | `0x26010` (`0x7fec3`) | MTD index | NAND boot device, non-recovery boot. |
| ` root=/dev/sd%c%d` | `0x2604c` (`0x7ff05`) | UFS LUN letter (`'a' + lun`) & partition index | UFS boot device, non-recovery boot. |
| ` androidboot.bootdevice=<dev>` | `0x26910` (`0x8003a`) | `FUN_0002514c` | When boot device string succeeds. |
| ` androidboot.serialno=<sn>` | `0x2693c` (`0x80053`) | `FUN_0001d4e0` (`%08x` chip serial at `0x9dc03`) | Always appended in `UpdateCmdLine`. |
| ` androidboot.mode=<mode> quite` | `0x2696c`, `0x26990` (`0x80172`, `0x80185`) | `BootReasonStr` (`FUN_0001fab4`/`PON`) | When non-empty boot mode string exists (note literal `' quite'` typo). |
| ` androidboot.mode=charger androidboot.baseband=lpm` | `0x269a4`, `0x269b8` (`0x8018c`, `0x801a6`) | Charger / PMIC PON off-mode charging check | Else-if off-mode charger flag (`[sp, #8] != 0`). |
| ` androidboot.alarmboot=true` | `0x26a00` (`0x801c0`) | PMIC PON alarm flag (`[sp, #0x14]`) | Else-if alarm boot flag set. |
| ` androidboot.baseband=<bb>` | `0x26a14` (`0x7ffa4`) | `FUN_00025b64` (`msm` / `apq` / etc.) | Always unless baseband invalid. |
| ` androidboot.slot_suffix=<_a/_b>` | `FUN_000260b4` | Active slot suffix from `BootInfo + 0x48` | Only when `MultiSlotBoot != 0`. |
| ` rootwait ro init=/init` | `0x2670c`, `0x26738` (`0x801f6`, `0x80209`) | Literal strings | When `system_as_root` / `BootIntoRecovery` condition holds. |
| ` skip_initramfs` | `0x26778` (`0x8020f`) | Literal string | When normal boot (`BootIntoRecovery == 0`) with `init=/init`. |
| `<DisplayPanelConfiguration>` | `0x267d4` -> `0x15d040` | UEFI variable `"DisplayPanelConfiguration"` (`gGuid_QcomTokenSpaceGuid`) | Appends panel config string (e.g., `mdss_mdp.panel=...`) if returned by DisplayDxe. |
| ` androidboot.dtbo_idx=%d` | `0x26868`, `0x26878` (`0x8023f`, `0x7ffbb`) | `FUN_0001fab4()` (`DAT_00156dcc`) | When `BootIntoRecovery == 0` and `GetDtboIdx() != -1`. |

### 4.3 Samsung `sec_update_cmdline` (`FUN_000706bc`, `0x800`-byte Buffer)

Every `snprintf` (`FUN_00004814`) site in `FUN_000706bc` was extracted and verified by `scripts/analyze_dtb_cmdline.py`:

| Parameter / Format | Call RVA(s) | String RVA | Data Source / Helper RVA | Condition / Notes |
|---|---|---|---|---|
| ` androidboot.sec_atd.tty=/dev/ttyMSM0` | `0x7080c` | `0x9dbab` | `FUN_00026c20` | Conditional on `FUN_00026c20` / ATD check. |
| ` androidboot.revision=%d` | `0x70908` | `0x9dbd1` | `FUN_000167f4` (`0x167f4`) | Board hardware revision (`hw_rev`). |
| ` console=ttyMSM0,115200,n8` | `0x709ec` | `0x9db6b` | `FUN_00012a5c() == 8` & `[sp+0x10] == 1` | Appended if `"console="` (`strstr` `0x31958`) not already present. |
| ` androidboot.ap_serial=0x%08x` | `0x70b10` | `0x9dbea` | `FUN_0001d878` (`0x1d878`) | SoC/AP serial number. |
| ` fg_reset=%d` | `0x70c14` | `0x9dc08` | `FUN_0001614c` (`0x1614c`) | Fuel-gauge reset flag. |
| ` sec_log=0x%x@0x%x` | `0x70e74` | `0x9dc15` | Hardcoded `0x200000` @ `0x85000000` (`0x70e60..0x70e68`) | Always (`2 MiB @ 0x85000000`). |
| ` sec_dbg=0x%x@0x%x` | `0x70f74` | `0x9dc28` | Hardcoded `0x1ff000` @ `0x84e00000` (`0x70f50..0x70f60`) | Always (`2044 KiB @ 0x84e00000`). |
| ` sec_dbg_ex_info=0x%x@0x%x` | `0x710e0` | `0x9dc3b` | Hardcoded `0xfc0` @ `0x84fff000` (`0x710c4..0x710d0`) | Always (`0xfc0 B @ 0x84fff000`). |
| ` androidboot.debug_level=0x4948` | `0x71218` | `0x9dc56` | `param` via `0x1914c`/`0x191a8`/`0x19268`/`0x19514` | When debug level == `0x47494844` (`"DHIG"`, HIGH). |
| ` androidboot.debug_level=0x4f4c` | `0x7129c` | `0x9dcfc` | Same | When debug level == `0x574f4c44` (`"DLOW"`, LOW). |
| ` androidboot.debug_level=0x494d` | `0x71320` | `0x9dcc3` | Same | When debug level == `0x44494d44` (`"DIMD"`, MID). |
| ` sec_debug.enable=1` / `0` | `0x713a4`, `0x71634`, `0x716bc` / `0x7148c` | `0x9dc76` / `0x9dd1c` | Derived from `debug_level` (`MID`/`HIGH` -> `1`, `LOW` -> `0`) | Enables/disables `sec_debug`. |
| ` sec_debug.enable_user=0` / `1` | `0x71744`, `0x71940`, `0x719c8` / `0x71a50` | `0x9dce3` / `0x9dc8a` | Derived from `debug_level` / user build check | `1` when HIGH debug level. |
| ` msm_rtb.enable=1` | `0x71ad8`, `0x71cdc`, `0x71ecc` | `0x9dcb1` | Debug level HIGH/MID branches | RTB logging enabled in debug modes. |
| ` slub_debug=o` | `0x71d64` | `0x9dca3` | Debug level branch | Enabled in debug mode. |
| ` androidboot.cp_debug_level=0x5500` / `0x55FF` | `0x71fd4` / `0x7205c` | `0x9dd30` / `0x9dd70` | CP debug param (`0x5500` vs `0x55FF`) | Controls modem/CP debug level. |
| ` sec_debug.enable_cp_debug=1` / `0` | `0x721a4` / `0x72230` | `0x9dd53` / `0x9dd93` | Derived from CP debug level | `1` if CP debug enabled, else `0`. |
| ` androidboot.cp_reserved_mem=on` / `off` | `0x723ac`, `0x72430` / `0x724b4` | `0x9ddb0` / `0x9ddd0` | `param` value `0x4d42` (`"BM"`) / `0x4350` (`"PC"`); sets `DAT_00168e6c \|= 2` | `on` when CP/BM reserved mem active, else `off`. |
| ` androidboot.force_upload=0x5` / `0x0` | `0x7267c`, `0x728e8` / `0x72718`, `0x727ac` | `0x9ddf1` / `0x9de0f` | `param` value `5` vs `0`; sets `DAT_00168e6c \|= 4` | Forces kernel panic upload mode when `0x5`. |
| ` androidboot.upload_offset=%u` | `0x72a3c` | `0x9de2d` | `FUN_00019204` (`param` + `0x3f4` = `1012`) | Offset in `param` partition (`FUN_00018388`). |
| ` androidboot.boot_recovery=1` / `0` | `0x72b2c` / `0x72bb0` | `0x9de4b` / `0x9de68` | `BootIntoRecovery` (`w21 & 0xff == 1`) | `1` in recovery mode, `0` otherwise. |
| ` androidboot.carrierid.param.offset=%u` | `0x72d2c` | `0x9de85` | `FUN_000192c4` (`param` + `0x1cc` = `460`) | Offset in `param` partition. |
| ` androidboot.carrierid=%a` | `0x72e1c` | `0x9deac` | `FUN_00019328` (`0x19328`) | Carrier ID string from `param`. |
| ` androidboot.sales.param.offset=%u` | `0x72f18` | `0x9dec6` | `FUN_000193a0` (`param` + `0x1d0` = `464`) | Offset in `param` partition. |
| ` androidboot.sales_code=%a` | `0x73000` | `0x9dee9` | `FUN_00019404` (`0x19404`) | CSC / Sales code string from `param`. |
| ` androidboot.prototype.param.offset=%u` | `0x73100` | `0x9df04` | `FUN_000194b0` (`param` + `0x1dc` = `476`) | Offset in `param` partition. |
| ` androidboot.verifiedbootstate=%a` | `0x731f8` | `0x9df2b` | `FUN_00007054` / `FUN_00007148` indexing `0x9fa60` | Table at `0x9fa60`: `["green", "yellow", "orange", "red"]`. |
| ` androidboot.warranty_bit=%d` | `0x732e0` | `0x9df4d` | Warranty fuse / `FUN_00007148` | `0` (intact) or `1` (tripped). |
| ` androidboot.wb.hs=%x` | `0x733e4` | `0x9df6a` | `FUN_0000bdfc` (`0xbdfc`) | Warranty bit history/fuse hex state. |
| ` androidboot.wb.snapQB=%a` | `0x734dc` | `0x9df80` | `FUN_0000be40` (`0xbe40`) | Snapdragon QuickBoot / WB status string. |
| ` androidboot.ucs_mode=%d` | `0x735cc` | `0x9df9a` | `FUN_00008730` (`0x8730`) | Samsung UCS (Universal Credential Storage) mode. |
| ` androidboot.em.did=%a` | `0x736c8` | `0x9dfb3` | `FUN_00010a78` (`0x10a78`) | Engineering Mode (EM) device ID. |
| ` androidboot.em.model=%a` | `0x737b4` | `0x9dfca` | Literal `"SM-A920F"` | Always `"SM-A920F"`. |
| ` androidboot.em.status=0x%x` | `0x738a4` | `0x9dfe3` | `FUN_00011454` (`0x11454`) | Engineering Mode token status. |
| ` androidboot.sb.debug0=0x%x` | `0x739ac` | `0x9dfff` | `FUN_000114b0` (`0x114b0`) | Appended only when `FUN_000114b0() != 0xff` (`0x73984`). |
| ` androidboot.swp_config=%d` | `0x73afc` | `0x9e01b` | `FUN_00070448(boot_recovery)` (`0x70448`) | Appended when boot device prefix matches `"UFS"` (`0x7cfe1`). |
| ` androidboot.bootloader=%a` | `0x73bf4` | `0x9e036` | Literal `"A920FXXS7CVH1"` | Bootloader version string. |
| ` afc_disable=0x%02x` | `0x73cf0` | `0x9e051` | `FUN_000190f0` (`0x190f0`) | Adaptive Fast Charging disable byte from `param`. |
| ` androidboot.security_mode=%d` | `0x73de8` | `0x9e065` | `FUN_000189d0` (`0x189d0`) | Security mode flag (also checks RKP/KAP fuses `0x73e00..0x73fc0`). |
| ` androidboot.dram_info=%02X,%02X,%02X,%dG` | `0x74018` | `0x9e18b` | `FUN_00016554` (SMEM `0x86`) + `FUN_0000a184` | LPDDR4 manufacturer/revision/density from SMEM (`0x86`). |
| ` androidboot.usrf=%u` | `0x74148` | `0x9e1b5` | `FUN_00018a74` (`0x18a74`) | Appended only when `FUN_00018a74() >= 1` (`0x74128`). |
| ` rbfib=%d` | `0x74240` | `0x9e1ca` | `FUN_00013244` (`0x13244`) | Rollback / recovery-fuse state. |
| ` ccic_info=%d` | `0x74334` | `0x9e1d4` | Hardcoded `1` (`0x74324: mov w3, #1`) | Always `ccic_info=1`. |

---

## 5. Verification

Running [`scripts/analyze_dtb_cmdline.py`](../scripts/analyze_dtb_cmdline.py) against `extracted/F/LinuxLoader.efi` and `decomp/F_LinuxLoader/functions.json` confirms all 42 referenced function RVAs, AArch64 instruction encodings (`0x2148..0x214c`, `0x23f0..0x2400`, `0x1e484..0x1e534`, `0x1ecc0..0x1ece4`, `0x2aa8c..0x2aab8`, `0x216b8..0x2170c`, `0x227a0`), `param` offsets (`0x3f4`, `0x1cc`, `0x1d0`, `0x1dc`), `0x9fa60` verifiedbootstate table, and all `snprintf` cmdline formats (`3` in `FUN_00025d54`, `1` in `FUN_000260b4`, `59` in `FUN_000706bc`).
