# SM-A920F vs SM-A920N vs SM-A9200 ABL Variant Comparison (`a9y18qlte`, SDM660)

Comparative reverse-engineering report for the Samsung Galaxy A9 (2018) (`a9y18qlte`, Qualcomm SDM660) Android Bootloader (`abl.elf`) across three regional/carrier builds:

| Variant | Region / Market | Build ID | Product Target (`AutoGen.c`) | Build Date (`LinuxLoader`) | Reproducible Script |
|---|---|---|---|---|---|
| **`SM-A920F`** (`F`) | Global / Europe (`EUR_XX_GBL0`) | `A920FXXS7CVH1` | `a9y18qlte` | `Aug 26 2022 19:11:41` | [`scripts/diff_variants.py`](../scripts/diff_variants.py) |
| **`SM-A920N`** (`N`) | South Korea (`KOR_KX_KOR0`) | `A920NKSU5CVG1` | `a9y18qltekx` | `Jul 21 2022 11:32:19` | [`scripts/diff_variants.py`](../scripts/diff_variants.py) |
| **`SM-A9200`** (`A9200`) | China / Hong Kong (`CHN_CHC_CHN0`) | `A9200ZHU5CZB1` | `a9y18qltechn` | `Mar 17 2026 20:20:53` | [`scripts/diff_variants.py`](../scripts/diff_variants.py) |

> **Address Convention**: Both `LinuxLoader.efi` and `Odin.efi` are PE32+ AArch64 (`0xaa64`) images with `ImageBase = 0x0`, so `VA == RVA == FileOffset` in all Ghidra exports (`decomp/{F,N,A9200}_{LinuxLoader,Odin}`) and extracted binaries (`extracted/{F,N,A9200}`).

---

## 1. Signing, MBN v5, X.509 Certificate & Container Diffs

All three `abl.elf` containers are identical in total size (**`2,109,952` bytes**, `0x203200`) and ELF wrapper geometry (`ELFCLASS64` / `EM_ARM`, entry `0x9fa00000`, `PT_LOAD` `0x200000` bytes at file offset `0x3000`, followed by a 512-byte Samsung `SignerVer02` trailer at `0x203000`).

### 1.1 `abl.elf` Container & `SignerVer02` Trailer (`0x203000..0x203200`)

| Field | `SM-A920F` (`F`) | `SM-A920N` (`N`) | `SM-A9200` (`A9200`) |
|---|---|---|---|
| **`abl.elf` SHA-256** | `54bb167978dd9a971d796b610ee0be47995e18aabcdbeb96504f66ab02fe7006` | `b6eab5c1678b44849ddfbfb5d76d60aa09fef2fcde06db5cc6a6e851a2d0ced1` | `6b925436edf48ae1da4cbb67899d849a6d62c4f03dddc142cc37833e5b0f3c9d` |
| **Segment 0 (`PT_NULL`, `0x0..0xe8`) SHA-256** | `d73d7ebdc76c3258f629031384c649ef8538a2aa98627e9a0fcda81a2472afdd` | *(identical)* | *(identical)* |
| **Segment 1 (MBN v5, `0x1000..0x2988`) SHA-256** | `2fa7ccb08b2c69115c7a4a3cd4b7a153e602fcc672d8794256713d4535dab5b4` | `5b49daaefc7213f3556a7bdadd3c05fb8de52462778de85313a91479387b08aa` | `5c3dbea034fe0f0140588ad2f7c27193e2bfacbd7747b779d6383fd429956d59` |
| **Segment 2 (`PT_LOAD`, `0x3000..0x203000`) SHA-256** | `06d5164935033b795f1c3969c4379d7632fc2573c5c9e6e6b79ed32f5c6c2ac7` | `12b4ac31c289818fce03270527f697def0a2dcf763b2464a9d9e3e66e83215f1` | `92be9eeff7edeb2fdaf2804871f582b520bacb72e439d02d7e3ce90e820e87e9` |
| **`SignerVer02` Magic (`+0x00`)** | `SignerVer02` | `SignerVer02` | `SignerVer02` |
| **Signer / QB Revision (`+0x10`)** | `55622970R` | `54198412R` | `107562819R` |
| **Build ID (`+0x20`)** | `A920FXXS7CVH1` | `A920NKSU5CVG1` | `A9200ZHU5CZB1` |
| **Build Timestamp (`+0x40`)** | `20220826192111` | `20220721114126` | `20260317203514` |
| **Project / Model ID (`+0x50`)** | `SM-A920F_EUR_XX_GBL0` | `SM-A920N_KOR_KX_KOR0` | `SM-A9200_CHN_CHC_CHN0` |
| **QuickBuild ID (`+0x70`, `+0x80`)** | `SRPRI18A007` | `SRPRJ17A005` | `RILRI18A005` |
| **Binary Name (`+0xb0`)** | `abl.elf` | `abl.elf` | `abl.elf` |
| **Build Host / CL (`LinuxLoader` `.rodata`)** | `SWDH2816` / CL `18245146` | `SWDH4611` / CL `24748664` | `21DI2701-VM01` / CL `20954136` |

### 1.2 Qualcomm MBN v5 & X.509 Certificate Chain (`0x1000..0x2988`)

All three images use **MBN v5** (`version = 5`, `code_size = 0x60` for 3 SHA-256 segment hashes, `sig_size = 0x100` for 2048-bit RSA-PSS, `cert_chain_size = 0x1800`) with a 3-certificate chain (`1327` + `1173` + `1165` bytes at segment 1 offsets `0x188`, `0x6b7`, `0xb4c`) issued by `Samsung Root CA cert` (`OU = DMC`, `m.security@samsung.com`):

| Certificate / OU Field | `SM-A920F` (`F`) | `SM-A920N` (`N`) | `SM-A9200` (`A9200`) |
|---|---|---|---|
| **Leaf `SW_ID` (`OU 01`)** | **`000000070000001C`** (RP rev **`7`**, img `0x1c`) | **`000000050000001C`** (RP rev **`5`**, img `0x1c`) | **`000000050000001C`** (RP rev **`5`**, img `0x1c`) |
| **Leaf `HW_ID` (`OU 02`)** | `3006000000200000` | `3006000000200000` | `3006000000200000` |
| **Leaf `DEBUG` (`OU 03`)** | `0000000000000002` | `0000000000000002` | `0000000000000002` |
| **Leaf `OEM_ID` (`OU 04`)** | `0020` (Samsung) | `0020` (Samsung) | `0020` (Samsung) |
| **Leaf `SW_SIZE` (`OU 05`)** | `00000088` | `00000088` | `00000088` |
| **Leaf `MODEL_ID` (`OU 06`)** | `0000` | `0000` | `0000` |
| **Leaf `SHA256` (`OU 07`)** | `0001` | `0001` | `0001` |
| **Leaf `IN_USE_SOC_HW_VERSION` (`OU 13`)** | `0001` | `0001` | `0001` |
| **Leaf `notBefore` (GMT)** | `Aug 26 10:18:46 2022` | `Jul 21 02:39:44 2022` | `Mar 17 11:32:04 2026` |
| **Leaf SHA-256** | `122aa0c608708364...` | `5c75f3eeb40ce855...` | `b6ee1463a0513ce4...` |
| **CA / Root Cert `notBefore`** | `Sep 18 08:27:36 2018` | `Oct 17 00:58:24 2018` | `Sep 18 08:29:40 2018` |

> **Key observation**: Hardware/OEM/Model IDs (`HW_ID = 3006000000200000`, `OEM_ID = 0020`, `MODEL_ID = 0000`) are **100% identical** across all three regional variants. Only the rollback version in `SW_ID` (`7` in `F` vs `5` in `N` and `A9200`), signing timestamps, and RSA-PSS signatures/certificates differ.

### 1.3 `OuterFV` and `InnerFV` Module Sizes

| Container / Module | `SM-A920F` (`F`) | `SM-A920N` (`N`) | `SM-A9200` (`A9200`) |
|---|---|---|---|
| **`OuterFV` FFS (`9e21fd93-...`) size** | `0xba6a8` (763,560 B) | `0xb4ecc` (741,068 B) | `0xba8d4` (764,116 B) |
| **`OuterFV` LZMA payload size** | `0xba690` | `0xb4eb4` | `0xba8bc` |
| **`InnerFV` decompressed size** | `0x287100` (2,650,368 B) | `0x2c0100` (2,883,840 B) | `0x289100` (2,658,560 B) |
| **`Odin.efi` FFS (`aba3b456-...`) size** | `0x11b02c` | `0x13b02c` | `0x11c02c` |
| **`Odin.efi` PE32+ size / SHA-256** | `1,159,168` B / `96a77ec846ee...` | `1,290,240` B / `622241cfa915...` | `1,163,264` B / `131487c661a6...` |
| **`LinuxLoader.efi` FFS (`f536d559-...`) size** | `0x16c038` | `0x185038` | `0x16d038` |
| **`LinuxLoader.efi` PE32+ size / SHA-256** | `1,490,944` B / `a67caa9a8d7d...` | `1,593,344` B / `fb0c22d7b9bd...` | `1,495,040` B / `b030b60f1f49...` |

Note that `N`'s `InnerFV` is **`+233,472` bytes (`+0x39000`)** larger uncompressed than `F`, yet compresses **smaller** (`0xb4eb4` vs `0xba690`) because the extra `.data` space is predominantly zero-padding inside fixed-stride JPEG image buffers (Section 2.2).

---

## 2. PE32+ Section Layouts & `.data` Payload Diffs

### 2.1 PE32+ Section Table Comparison

| Module | Section | `SM-A920F` (`F`) | `SM-A920N` (`N`) | `SM-A9200` (`A9200`) |
|---|---|---|---|---|
| **`LinuxLoader.efi`** | `.text` | `0x1000`, size `0x9e000` | `0x1000`, size `0x9e000` (`+0x0`) | `0x1000`, size `0x9e000` (`+0x0`) |
| **`LinuxLoader.efi`** | `.data` | `0x9f000`, size `0xca000` | `0x9f000`, size **`0xe3000`** (`+0x19000` / `+102,400 B`) | `0x9f000`, size **`0xcb000`** (`+0x1000` / `+4,096 B`) |
| **`LinuxLoader.efi`** | `.reloc` | `0x169000`, size `0x3000` | `0x182000`, size `0x3000` | `0x16a000`, size `0x3000` |
| **`Odin.efi`** | `.text` | `0x1000`, size `0x77000` | `0x1000`, size **`0x78000`** (`+0x1000`) | `0x1000`, size **`0x78000`** (`+0x1000`) |
| **`Odin.efi`** | `.data` | `0x78000`, size `0xa0000` | `0x79000`, size **`0xbf000`** (`+0x1f000` / `+126,976 B`) | `0x79000`, size `0xa0000` (`+0x0`) |
| **`Odin.efi`** | `.reloc` | `0x118000`, size `0x3000` | `0x138000`, size `0x3000` | `0x119000`, size `0x3000` |

### 2.2 Why `SM-A920N` (`.data`) Is `0x19000` / `0x1f000` Larger (and `SM-A9200` Is `+0x1000` in `LinuxLoader`)

Scanning `.data` for `FF D8 FF ... FF D9` JPEG streams reveals that **100% of the `.data` size growth in `SM-A920N` and `SM-A9200` comes from embedded UI/boot-logo JPEG C-arrays** (no extra carrier logo sets or Hangul bitmap fonts were added to `sysfont2x`):

1. **Fixed-Stride 2D JPEG C-Arrays in `SM-A920N` (`Odin.efi` `+0x1f000`, `LinuxLoader.efi` `+0x19000`)**:
   - Samsung compiles localized Download Mode / Warning UI text lines as static 2D byte arrays `uint8_t img_table[N][MAX_SLOT_SIZE]`, zero-padded to the largest JPEG in each group.
   - **Download Mode Main UI Array (9 JPEGs)**:
     - In `F` (`0x7aad4..0xa1114` in `Odin.efi`; `0xafb48..0xd6188` in `LinuxLoader.efi`) and `A9200` (`0x7bad4..0xa2114` in `Odin.efi`; `0xafb48..0xd6188` in `LinuxLoader.efi`), the 9 slots use stride **`0x4cc8`** (`19,656` B/slot, sized to `904x176`).
     - In `N` (`0x7bad4..0xbb944` in `Odin.efi`; `0xa9de8..0xe9c58` in `LinuxLoader.efi`), the 2nd Korean Hangul UI JPEG (`1008x176`, at `0x83aa2` in `Odin.efi` / `0xb1db6` in `LinuxLoader.efi`) is **`32,718` bytes (`0x7fce`)**, forcing all 9 slots to expand to stride **`0x7fce`** (`+0x3306` bytes/slot across 9 slots = **`+0x1d136` / `+119,094` B** of mostly trailing zero padding!).
   - **Secondary Warning/Status Array (5 JPEGs)**:
     - In `F` (`0xa5e18..0xafe84` in `Odin.efi`; `0xf0e08..0xfae74` in `LinuxLoader.efi`) and `A9200`, the 5 slots use stride **`0x281b`** (`10,267` B/slot).
     - In `N` (`0xc3950..0xcf194` in `Odin.efi`; `0x107be0..0x113424` in `LinuxLoader.efi`), the 5 slots expand to stride **`0x2e11`** (`11,793` B/slot, **`+0x1dce` / `+7,630` B**).
     - Combined in `Odin.efi`: `0x1d136 + 0x1dce = 0x1ef04`, rounding `.data` up by **`+0x1f000`** (`0xbf000` vs `0xa0000`).
   - **Warning Banner Array in `LinuxLoader.efi` (`0x152c4` in `F`/`A9200` vs `0x1541c` in `N`)**:
     - `F` and `A9200` store **6 JPEGs** (`0x9fda8..0xad0a7`, stride `0x2a33`), whereas `N` stores **4 Korean JPEGs** (`0x9fd90..0xa7581`, stride `0x27fb`), saving `~0x5f00` bytes. Net `.data` delta in `N` `LinuxLoader.efi` is `+0x1ef04 - 0x5f00 ≈ +0x19000` (`0xe3000` vs `0xca000`).
2. **`SM-A9200` `.data` Growth in `LinuxLoader.efi` (`0xcb000` vs `0xca000`, `+0x1000`)**:
   - The 4 boot-logo JPEGs rendered by `GlibDrawBootImage` (`0xdae80..0xe57dc` in `F`, `0xdae80..0xe5cfb` in `A9200`) are slightly larger in `A9200` (`736x112`, `13,504` B vs `720x120`, `12,862` B), increasing the 4-slot stride from `0x3874` to `0x3a29` (`+0x6d4` bytes across 4 slots) and pushing `.data` across a `0x1000` page boundary.

### 2.3 Non-JPEG `.rodata` / `.data` String Diffs

Excluding build-time metadata (`SM-A920F`/`SM-A920N`/`SM-A9200`, `a9y18qlte`/`a9y18qltekx`/`a9y18qltechn`, `SWDH2816`/`SWDH4611`/`21DI2701-VM01`, CL/QB IDs, and compile timestamps) and localized UI JPEGs:
- **`N`-only strings**:
  - `"Invalid parameter, pleae check BlockIo info!!!\n"`
  - `"Integer overflow while adding LastBlock and 1\n"`
  - `"Integer overflow while multiplying LastBlock and BlockSize\n"`
  - `"KOR"` (`0x7b666` in `LinuxLoader.efi`, `0x5b9a5` in `Odin.efi`)
- **`A9200`-only strings**:
  - `" FRP is enabled, not allowed to download non-FRP %a binary"` (`0x79700` in `LinuxLoader.efi`, `0x5a88a` in `Odin.efi`)
  - `"frp"` (`0x796f8` in `LinuxLoader.efi`, `0x5a886` in `Odin.efi`)
  - `" FRP is enabled, ignore PIT download"` (`0x565db` in `Odin.efi`)
  - `"Re-initialize : PIT"` (`0x565ff` in `Odin.efi`)
  - `"CHN"` (`0x7b6a4` in `LinuxLoader.efi`, `0x5ba85` in `Odin.efi`), `"HK"` (in `GlibDrawBootImage` / param init)
- **`F` & `N` only (absent in `A9200`)**: `"OPEN"` (`0x7add0` in `F`, `0x7afd0` in `N` `LinuxLoader.efi`; replaced by `"HK"` in `A9200`).

---

## 3. Code & Behavior Diffs (`LinuxLoader.efi` & `Odin.efi`)

Capstone-normalized function matching across all `1224`/`1224`/`1225` functions in `LinuxLoader.efi` and `872`/`873`/`873` functions in `Odin.efi`—plus mnemonic matching over uncovered `.text` gaps (such as `Odin.efi`'s main command dispatcher at `0x47b4..0x68c0` / `0x6954`)—reveals that **>99% of the codebase is identical**. Every genuine behavioral/code difference falls into five specific areas:

### 3.1 Summary Matrix of Modified / Added Functions

| Area / Behavior | `F` RVA (Size) | `N` RVA (Size) | `A9200` RVA (Size) | Classification |
|---|---|---|---|---|
| **1. `SW_ID` Cert Parser (`LinuxLoader`)** | `0xd3a8` (`440 B`) | `0xd39c` (`792 B`) | `0xd3d0` (`792 B`) | **Logic Diff**: Decimal-only (`F`) vs Hex (`N`/`A9200`) |
| **1b. `SW_ID` Cert Parser (`Odin`)** | `0x14dd8` (`440 B`) | `0x14dd8` (`792 B`) | `0x14e90` (`792 B`) | **Logic Diff**: Decimal-only (`F`) vs Hex (`N`/`A9200`) |
| **2. Hardcoded System/Kernel RP (`LinuxLoader`)** | `0xd560`, `0xd59c` (`60 B`) | `0xd6b4`, `0xd6f0` (`60 B`) | `0xd6e8`, `0xd724` (`60 B`) | **Constant Diff**: Returns `7` (`F`) vs `5` (`N`/`A9200`) |
| **2b. Hardcoded System/Kernel RP (`Odin`)** | `0x14f90`, `0x14fcc` (`60 B`) | `0x150f0`, `0x1512c` (`60 B`) | `0x151a8`, `0x151e4` (`60 B`) | **Constant Diff**: Returns `7` (`F`) vs `5` (`N`/`A9200`) |
| **3. FRP Non-FRP Binary Check (`LinuxLoader`)** | *(absent)* | *(absent)* | **`0xdc2c`** (`180 B`, new) | **Added (`A9200`)**: Blocks non-FRP binary if FRP on |
| **3b. FRP Non-FRP Binary Check (`Odin`)** | *(absent)* | *(absent)* | **`0x156ec`** (`180 B`, new) | **Added (`A9200`)**: Blocks non-FRP binary if FRP on |
| **3c. `SecurityCheck` (`LinuxLoader`)** | `0x80c8` (`3108 B`) | `0x80bc` (`3108 B`) | `0x80c8` (`3148 B`) | **Modified (`A9200`)**: Calls `0xd760` + `0xdc2c` |
| **3d. `SecurityCheck` (`Odin`)** | `0xfff4` (`3108 B`) | `0xfff4` (`3108 B`) | `0x10084` (`3148 B`) | **Modified (`A9200`)**: Calls FRP binary check `0x156ec` |
| **3e. Odin Main Loop PIT+FRP Guard (`Odin`)** | `0x47b4..0x68c0` (`8460 B`) | `0x47b4..0x68c0` (`8460 B`) | `0x47b4..0x6954` (`8608 B`) | **Modified (`A9200`)**: `0x6304..0x6310` -> `0x48d0..0x4920` |
| **4. `GetPartitionSize` Overflow Helper (`LinuxLoader`)** | *(absent)* | **`0x282c4`** (`236 B`, new) | *(absent)* | **Added (`N`)**: `LastBlock+1 * BlockSize` overflow check |
| **4b. `GetPartitionSize` Overflow Helper (`Odin`)** | *(absent)* | **`0x204fc`** (`236 B`, new) | *(absent)* | **Added (`N`)**: `LastBlock+1 * BlockSize` overflow check |
| **4c. Storage/AVB Callers of `GetPartitionSize`** | `0x3294..0x452c`, `0x25998`, `0x26fc4`, `0x2818c` (`LL`); `0x1f9b0`, `0x20908` (`Odin`) | `0x3294..0x4520`, `0x25ac8`, `0x270fc`, `0x283b0` (`LL`); `0x1fb14`, `0x20b60` (`Odin`) | *(same as `F`, shifted)* | **Modified (`N`)**: Calls `0x282c4` / `0x204fc` (+ `__LINE__` shifts in `0x27850`, `0x293c4`, `0x29f04`, `0x2a218`) |
| **5. `GlibDrawBootImage` (`LinuxLoader`)** | `0x14ba0` (`776 B`) | `0x14cf4` (`776 B`) | `0x14ddc` (`776 B`) | **String/Asset Diff**: `"OPEN"` (`F`/`N`) vs `"HK"` (`A9200`) |
| **5b. Warning Screen JPEGs (`LinuxLoader`)** | `0x152c4` (`212 B`) | `0x1541c` (`172 B`) | `0x15500` (`212 B`) | **UI Asset Diff (`N`)**: 6 JPEGs (`F`/`A9200`) vs 4 JPEGs (`N`) |
| **5c. Secondary Banner Stride (`LinuxLoader`)** | `0x15398` (`192 B`) | `0x154c8` (`192 B`) | `0x155d4` (`192 B`) | **Stride Constant (`N`)**: `0x281b` vs `0x2e11` |
| **5d. Param Default Sales Code (`LinuxLoader`)** | `0x1991c` (`576 B`) | `0x19a4c` (`576 B`) | `0x19b58` (`576 B`) | **Region Macro Diff**: `"EUR"`/`"OPEN"` vs `"KOR"`/`"OPEN"` vs `"CHN"`/`"HK"` |

*(Note: Minor `SequenceMatcher` hits such as `F` `0x2ee8` `56 B` unreferenced stub, `N` `0x3604` sparse-superblock helper with identical logic, `0x14f34`/`0x15088`/`0x1ad44`/`0x1aea4` JPEG coordinate pointers, `0x234e8` `sec_debug`, `0x29cd0` `HandleActiveSlotUnbootable`, `0x3c7ac` `Device IP`, and `ArmLib` EL-register stubs `0x32d60`/`0xa3ec` were manually verified to have identical control flow.)*

---

### 3.2 `SW_ID` Certificate Rollback Parser & Hardcoded RP Constants

In `LinuxLoader` (`0xd3a8` `F`, `0xd39c` `N`, `0xd3d0` `A9200`) and `Odin` (`0x14dd8` `F`/`N`, `0x14e90` `A9200`), ABL scans the X.509 certificate subject for `"SW_ID"` and reads the 8 ASCII characters preceding it (`param_1 + (idx - 0x11)`) to extract the 32-bit rollback version:
- **`SM-A920F` (`440` bytes)**: Accepts **only ASCII `'0'..'9'`** (`(byte)c - 0x30 <= 9`), otherwise prints `"SW_ID value has been corrupted\n"` and returns `0`.
- **`SM-A920N` & `SM-A9200` (`792` bytes)**: Parses **full hexadecimal** (`'0'..'9'`, `'A'..'F'`, `'a'..'f'`) using `-0x30`, `-0x37`, `-0x57` nibble adjustments.

Adjacent getter stubs initialize `DAT_0009f99c` and `DAT_0009f9a0` inside `SecurityStatusInit` (`0x71a0` in `F`):
- **`SM-A920F`**: `0xd560` / `0xd59c` (`LinuxLoader`) and `0x14f90` / `0x14fcc` (`Odin`) return **`7`**.
- **`SM-A920N`**: `0xd6b4` / `0xd6f0` (`LinuxLoader`) and `0x150f0` / `0x1512c` (`Odin`) return **`5`**.
- **`SM-A9200`**: `0xd6e8` / `0xd724` (`LinuxLoader`) and `0x151a8` / `0x151e4` (`Odin`) return **`5`**.

---

### 3.3 `SM-A9200` (`A9200ZHU5CZB1`) FRP-Protected Binary & PIT Download Enforcement

Unique to the 2026 China/HK (`SM-A9200`) build, Samsung added **two new FRP enforcement checks** in both `LinuxLoader.efi` and `Odin.efi` to prevent flashing older/non-FRP-tagged images or repartitioning via PIT while Factory Reset Protection (FRP) is locked:

#### A. Non-FRP Binary Rejection (`0xdc2c` in `A9200_LinuxLoader`, `0x156ec` in `A9200_Odin`)
Called from `SecurityCheck` (`0x80c8` in `A9200_LinuxLoader`, `0x10084` in `A9200_Odin`) for both **booting** (`ImageHandle[2] == 1`, `boot`/`recovery`) and **Odin flashing** (`ImageHandle[2] == 2`, all partitions except `xbl`/`abl`-type `0` and `modem` `0xd`):
```c
// A9200_LinuxLoader @ 0xdc2c (and A9200_Odin @ 0x156ec)
if (param_1[0xb] != 2) {                          // if no SignerVer02 trailer
    ZeroMem(&DAT_00158788, 0x100);                // clear SignerVer02 buffer
}
puVar4 = GetSecurityStatus();                     // &DAT_0009f990 (F) / Odin 0xf170
// puVar4[0xc] = FRP Lock flag (nonzero = ON), puVar4[0xd] = OEM Unlock flag (0 = LOCKED)
if ((puVar4[0xc] != 0) && (puVar4[0xd] == 0) &&
    (AsciiStrnCmp(&DAT_0015881c, "frp", 3) != 0)) { // SignerVer02 + 0x94 != "frp"
    DrawScreen(0xff0000, " FRP is enabled, not allowed to download non-FRP %a binary");
    param_1[3] = 9;                               // Error code 9 ("CROSSDOWNLOAD")
    *param_1 = 1;                                 // Security check FAIL
}
```
Notice how `A9200` inspects offset **`+0x94`** inside the copied `SignerVer02` header (`0x15881c - 0x158788 = 0x94` in `LinuxLoader.efi`; `0x10d201 - 0x10d16d = 0x94` in `Odin.efi`) for the 3-byte tag `"frp"` (`0x796f8` / `0x5a886`). Notice also that it reuses error code **`9`** (`CROSSDOWNLOAD` in table `0x9fb08`), causing `SecurityCheck` to additionally log `"not allowed to download by crossdownload feature\n"`.

#### B. PIT Download Lockout in Odin Main Loop (`A9200_Odin` `0x6304..0x6310` → `0x48d0..0x4920`)
In `Odin.efi`'s main protocol dispatcher (`0x47b4..0x6954`, uncovered by Ghidra function boundaries), `A9200` inserts a pre-PIT-write check at `0x6304`:
```asm
; A9200_Odin @ 0x6304..0x6310 (F_Odin / N_Odin jump directly to 0x6290)
0x06304: ldr  w7, [x24, #0x30]   ; puVar4[0xc] = FRP Lock
0x06308: cbz  w7, #0x6314        ; skip if FRP OFF
0x0630c: ldr  w1, [x24, #0x34]   ; puVar4[0xd] = OEM Unlock
0x06310: cbz  w1, #0x48d0        ; if FRP ON && OEM Unlock == 0 -> block PIT!
```
At `0x48d0`, `A9200_Odin` displays `" FRP is enabled, ignore PIT download"` (`0x1abb4`), calls `ReadPitPartition()` (`0x8674`) to reload the on-device PIT, logs `"Re-initialize : PIT"` (`0x1e6bc`), and aborts PIT flashing.

---

### 3.4 `SM-A920N` (`A920NKSU5CVG1`) `GetPartitionSize` Integer-Overflow Hardening

Unique to `SM-A920N` (`Jul 21 2022`), ABL introduces a dedicated `GetPartitionSize(BlockIo)` helper (`0x282c4` in `N_LinuxLoader`, `0x204fc` in `N_Odin`, `236` bytes):
```c
// N_LinuxLoader @ 0x282c4 (and N_Odin @ 0x204fc)
if (BlockIo == NULL) {
    DEBUG((EFI_D_ERROR, "Invalid parameter, pleae check BlockIo info!!!\n"));
    return 0;
}
LastBlock = BlockIo->Media->LastBlock;
if (LastBlock == -1) {
    DEBUG((EFI_D_ERROR, "Integer overflow while adding LastBlock and 1\n"));
    return 0;
}
NumBlocks = LastBlock + 1;
BlockSize = BlockIo->Media->BlockSize;
if (BlockSize > (0xffffffffffffffffULL / NumBlocks)) {
    DEBUG((EFI_D_ERROR, "Integer overflow while multiplying LastBlock and BlockSize\n"));
    return 0;
}
return NumBlocks * BlockSize;
```
In `N`, this helper replaces inline `(LastBlock + 1) * BlockSize` multiplication in:
- **Both modules**: `EraseBlock` (`0x25ac8` `LL` / `0x1fb14` `Odin`), and `UpdateGpt` (`0x20b60` `Odin`).
- **`N_LinuxLoader` only**: `AvbGetSizeOfPartition` / `AvbReadFromPartition` (`0x3294..0x4520`), `ReadFromPartition` (`0x270fc`), `GetActiveSlot` (`0x27850`), `PartitionUpdate`/`Lun` (`0x283b0`), `SetActiveSlot` (`0x293c4`), `HandleActiveSlotUnbootable` (`0x29f04`), and `FindBootableSlot` (`0x2a218`). *(This shifts `__LINE__` constants in `PartitionTableUpdate.c` by `+0x20` = `+32` lines, e.g., `0x4ee` → `0x50e` in `SetActiveSlot`.)*
- **Neither `F` (`Aug 26 2022`) nor `A9200` (`Mar 17 2026`)** includes this `GetPartitionSize` overflow helper!

---

### 3.5 Regional Carrier, Boot Image & Command-Line Behavior Across All 3 Variants

Despite regional packaging (`EUR`, `KOR`, `CHN`), **none of the three ABL binaries contain SKT / KT / LGU+ carrier-specific checks or distinct `androidboot.carrierid` generation logic**. All three share the exact same kernel command-line generator (`0x706bc` in `F`, `0x708bc` in `N` and `A9200`), which reads the carrier/sales code from `param` via `0x19404` (`F`) / `0x19534` (`N`) / `0x19640` (`A9200`) and appends ` androidboot.carrierid.param.offset=%u` and ` androidboot.carrierid=%a`.

Compile-time regional macros (`TARGET_REGION` / `TARGET_CARRIER`) and common security checks behave as follows:

1. **Compile-Time Region & Carrier Strings (`0x1991c` `F`, `0x19a4c` `N`, `0x19b58` `A9200`)**:
   - In the `param` reset/initialization routine:
     - `F`: `strncmp("EUR", "USA", 3) == 0 && strncmp("OPEN", "SINGLE", 6) != 0` → copies `"OPEN"`
     - `N`: `strncmp("KOR", "USA", 3) == 0 && strncmp("OPEN", "SINGLE", 6) != 0` → copies `"OPEN"`
     - `A9200`: `strncmp("CHN", "USA", 3) == 0 && strncmp("HK", "SINGLE", 6) != 0` → copies `"HK"`
   - Because `"EUR"`, `"KOR"`, and `"CHN"` never equal `"USA"`, this fallback branch is dead code at runtime in all three builds.
   - Similarly, `GlibDrawBootImage` (`0x14ba0` `F`, `0x14cf4` `N`, `0x14ddc` `A9200`) checks `strncmp("OPEN", "DCM", 3)` (`F`/`N`) vs `strncmp("HK", "DCM", 3)` (`A9200`) before stalling 2 seconds for NTT Docomo (`DCM`), which also evaluates false in all three builds.

2. **Model Name & Build Display**:
   - `LinuxLoaderEntry` (`0x1794` in all 3) and `PrintBoardInfo` (`0x16874` `F`, `0x169a4` `N`, `0x16ab0` `A9200`; `Odin` `0x1b688` `F`, `0x1b7ec` `N`, `0x1b954` `A9200`) print `"SM-A920F"`, `"SM-A920N"`, or `"SM-A9200"` respectively.

3. **`Carrier Mismatch!` (`0x12b9c` `case 0x2c` → `0x1794`)**:
   - Identical across `F`, `N`, and `A9200`: if `QcomResetReasonProtocol` returns boot/reset reason `0x2c`, `FUN_00012b9c` (`F`) returns `8`, causing `LinuxLoaderEntry` (`0x1794`) to print `"Carrier Mismatch!\n"` and display `" Carrier Mismatch! Please download correct carrier binaries"` in red (`0xff0000`) before waiting for power-off.

4. **`C-ROM` / `KIWILOCK` (`0x7f3c` `F`/`A9200`, `0x7f30` `N` in `LinuxLoader`; `0xfed4` `F`/`N`, `0xff64` `A9200` in `Odin`)**:
   - Identical across all 3 variants: error code `8` (`"KIWILOCK"` in `0x9fb08`) displays `" Custom Binary (%a) Blocked By C-ROM"` in red (`0xff0000`), and in Odin sparse/raw mode (`ImageHandle[2] == 2, ImageHandle[1] == 0xe, ImageHandle[0xd] == 1`) calls `FUN_00007380` (`F`) to write `"KIWILOCK"` to the target partition header before rebooting. Note: no CROM-unlock app/partition check differs in `A9200` vs `F`/`N`; all three instead use the standard `persistent` partition OEM unlock flag (`0xc6fc` `F`, `0xc6f0` `N`, `0xc724` `A9200`).

5. **`CROSSDOWNLOAD` (`code 9`) & `Binaries are mixed up!!` (`0xddb0` `F`, `0xdf04` `N`, `0xdfec` `A9200`)**:
   - Error code `9` (`"CROSSDOWNLOAD"` in `0x9fb08`) logs `"not allowed to download by crossdownload feature\n"` in all 3 variants, and in **`SM-A9200` only** is actively triggered by `0xdc2c` (`LinuxLoader`) / `0x156ec` (`Odin`) for non-FRP binaries.
   - `CheckMixedBinaries` (`0xddb0` `F`, `0xdf04` `N`, `0xdfec` `A9200`; `Odin` `0x157e0` `F`, `0x15940` `N`, `0x15aac` `A9200`) compares bit 3 (`& 8`) of `SignerVer02 + 0x98` (`param_1 + 0x38`) across `boot`/`recovery`, `system`, `vendor`, and `odm` against the fused/ABL bit (`puVar4[0x22] & 8`), halting with `"Binaries are mixed up!! : %d %d %d %d %d"` if mismatched.

6. **Common Carrier Checks (`VZW`, `SPR`)**:
   - All 3 variants retain unused US-carrier checks: `"VZW"` low-battery check (`0x13758` `F`) and Download Mode `WARRANTY VOID` hide-for-VZW check (`Odin` `0x1b404` `F`, `0x1b568` `N`, `0x1b6d0` `A9200`), plus `"SPR"`/`"BST"`/`"VMU"`/`"XAS"` RTN config check (`Odin` `0x5868` `F`/`N`, `0x58c8` `A9200`).
