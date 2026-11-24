# SM-A920F (a9y18qlte) ABL UEFI Architecture and Bootflow

**Target Firmware**: Samsung Galaxy A9 2018 (`SM-A920F`, `a9y18qlte`, SDM660) — `A920FXXS7CVH1`  
**Build Info (embedded in `LinuxLoader.efi` / `Odin.efi`)**: `Aug 26 2022 19:11:41` (`DEBUG_CLANG35`, `AARCH64`)  
**ImageBase Convention**: Both `LinuxLoader.efi` and `Odin.efi` are PE32+ AArch64 (`0xaa64`) UEFI applications with `ImageBase = 0x0`, so `VA == RVA == FileOffset` throughout the decompiled Ghidra databases (`decomp/F_LinuxLoader`, `decomp/F_Odin`).  
**Verification Script**: [`scripts/analyze_uefi_bootflow.py`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/scripts/analyze_uefi_bootflow.py)

---

## 1. Container Layout & DDR Memory Map

### 1.1 `abl.elf` ELF64 (`EM_ARM`) & MBN v5 Wrapper

The flashable `abl.elf` image (`2,109,952` bytes = `0x203200`, SHA-256 `54bb167978dd9a971d796b610ee0be47995e18aabcdbeb96504f66ab02fe7006`) uses Qualcomm's hybrid ELF header format: `EI_CLASS = ELFCLASS64` (`2`, 64-bit ELF header `0x40` bytes + 3×56-byte program headers = `0xe8` bytes) paired with `e_machine = EM_ARM` (`0x28`) and entry point `0x9fa00000`.

| File Offset | Size | Segment / Region | PAddr / VAddr | Flags / Details | SHA-256 (verified) |
| --- | --- | --- | --- | --- | --- |
| `0x000000`–`0x0000e8` | `0xe8` | ELF64 Header + 3 PHDRs (`PHDR[0]`, `PT_NULL`) | `0x0` | `e_ehsize=64`, `e_phentsize=56`, `e_phnum=3`, `p_flags=0x7000000` | `d73d7ebdc76c3258f629031384c649ef8538a2aa98627e9a0fcda81a2472afdd` |
| `0x0000e8`–`0x001000` | `0xf18` | Zero padding | — | Page alignment to `0x1000` | — |
| `0x001000`–`0x002988` | `0x1988` | Qualcomm MBN v5 Hash Segment (`PHDR[1]`, `PT_NULL`) | `0x9fc00000` (`memsz=0x2000`) | `p_flags=0x2200000`; version `5`, `code_size=0x60` (3×SHA-256 hashes), `sig_size=0x100`, `cert_chain_size=0x1800` | `2fa7ccb08b2c69115c7a4a3cd4b7a153e602fcc672d8794256713d4535dab5b4` |
| `0x002988`–`0x003000` | `0x678` | Padding | — | Alignment to `0x3000` | — |
| `0x003000`–`0x203000` | `0x200000` | Outer UEFI FV0 (`PHDR[2]`, `PT_LOAD`) | `0x9fa00000` (`memsz=0x200000`) | `p_flags=0x7` (`R|W|X`); 2 MiB Firmware Volume (`_FVH`) | `06d5164935033b795f1c3969c4379d7632fc2573c5c9e6e6b79ed32f5c6c2ac7` |
| `0x203000`–`0x203200` | `0x200` | Samsung `SignerVer02` Footer | — | Appended outside ELF PHDRs (`512` bytes) | — |

#### MBN v5 Hash Segment (`0x1000`–`0x2988`) & X.509 Certificate Chain

The 40-byte MBN v5 header at `0x1000` (`header_words = [0x0, 0x5, 0x0, 0x0, 0x1960, 0x60, 0xffffffff, 0x100, 0xffffffff, 0x1800]`) is immediately followed at `0x1028` by three 32-byte SHA-256 segment digests:
1. Hash `[0]` (`0x1028`): `d73d7ebdc76c3258...` — matches `PHDR[0]` (`0x0..0xe8`).
2. Hash `[1]` (`0x1048`): `0000...0000` — zeroed placeholder for the hash segment itself.
3. Hash `[2]` (`0x1068`): `06d5164935033b79...` — matches `PHDR[2]` (`0x3000..0x203000`).

After the 256-byte (`0x100`) RSA signature at `0x1088`–`0x1188`, the `0x1800`-byte certificate buffer at `0x1188` holds 3 DER-encoded X.509 certificates:

| Index | Offset (`abl.elf`) | Length | Subject / Attestation OUs | Issuer | Serial | Validity |
| --- | --- | --- | --- | --- | --- | --- |
| `Cert[0]` | `0x1188` | `1327` B | `CN=SecTools Test User, O=SecTools`, `OU=01 000000070000001C SW_ID`, `OU=02 3006000000200000 HW_ID`, `OU=04 0020 OEM_ID`, `OU=05 00000088 SW_SIZE`, `OU=06 0000 MODEL_ID`, `OU=07 0001 SHA256`, `OU=03 0000000000000002 DEBUG`, `OU=13 0001 IN_USE_SOC_HW_VERSION` | `Samsung Root CA cert` (`m.security@samsung.com`) | `01` | `Aug 26 2022` – `Aug 21 2042` |
| `Cert[1]` | `0x16b7` | `1173` B | `Samsung Root CA cert` | `Samsung Root CA cert` | `05` | `Sep 18 2018` – `Sep 13 2038` |
| `Cert[2]` | `0x1b4c` | `1165` B | `Samsung Root CA cert` | `Samsung Root CA cert` | `D31E82F895DFA8C0` | `Sep 18 2018` – `Oct 18 2018` |

#### Samsung `SignerVer02` 512-Byte Footer (`0x203000`–`0x203200`)

- `+0x000` (`16` B): `"SignerVer02"` (magic)
- `+0x010` (`16` B): `"55622970R"` (signer ID)
- `+0x020` (`32` B): `"A920FXXS7CVH1"` (build ID; rollback rev `7`)
- `+0x040` (`16` B): `"20220826192111"` (signing timestamp `YYYYMMDDHHMMSS`)
- `+0x050` (`32` B): `"SM-A920F_EUR_XX_GBL0"` (project / region / carrier tag)
- `+0x070` (`16` B): `"SRPRI18A007"` (build server ID 1)
- `+0x080` (`16` B): `"SRPRI18A007"` (build server ID 2)
- `+0x090` (`8` B): `"usr"`, `+0x098` (`4` B): `"mrk"`, `+0x09c` (`96` B): `"abl.elf"`
- `+0x100` (`256` B): 2048-bit RSA signature (`SHA-256` of sig bytes: `401345a2a5f34396...` prefix `401345a2...`).

### 1.2 Outer FV0 → LZMA Section → Inner FV → `Odin.efi` + `LinuxLoader.efi`

1. **Outer FV0 (`0x3000`–`0x203000`, `0x200000` bytes)**:
   - `EFI_FIRMWARE_VOLUME_HEADER`: signature `_FVH` at `0x3028`, FileSystem GUID `8c8ce578-8a3d-4f1c-9935-896185c32dd3` (`EfiFirmwareFileSystem2Guid`), `HeaderLength = 0x48`, `FvLength = 0x200000`.
   - Single FFS file at `0x3048`: GUID `9e21fd93-9c72-4c15-8c4b-e77f1db2d792` (`AblCompressedFvGuid`), `Type = 0x0b` (`EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE`), `Size = 0xba6a8`.
   - GUIDed section at `0x3060`: `Type = 0x02` (`EFI_SECTION_GUID_DEFINED`), `Size = 0xba690`, GUID `ee4e5898-3914-4259-9d6e-dc7bd79403cf` (`LzmaCustomDecompressGuid`), `DataOffset = 0x18`.
   - LZMA payload (`0x3078`, `0xba678` bytes) decompresses to `2,650,376` (`0x287108`) bytes: a 4-byte `0x19` raw section marker (`04 00 00 19`) + 4-byte `0x17` (`EFI_SECTION_FIRMWARE_VOLUME_IMAGE`, `04 71 28 17`) header, followed at `+8` by `inner_fv.bin` (`2,650,368` = `0x287100` bytes, SHA-256 `49898645a7f14ce944b7517247dd73e5b17e22e3714c617dba637029b3beb9f7`, verified byte-identical to `extracted/F/inner_fv.bin`).
2. **Inner FV (`inner_fv.bin`, `0x287100` bytes)**:
   - `EFI_FIRMWARE_VOLUME_HEADER` (`0x00`–`0x48`): `EfiFirmwareFileSystem2Guid`, `HeaderLength = 0x48`, `FvLength = 0x287100`.
   - Pad FFS (`0x48`–`0x74`): `Type = 0xf0` (`EFI_FV_FILETYPE_FFS_PAD`), size `0x2c`, aligning next FFS to `0x78`.
   - **`Odin` FFS (`0x78`–`0x11b0a4`)**: GUID `aba3b456-5469-414a-9f79-47cecbd7c04e`, `Type = 0x09` (`EFI_FV_FILETYPE_APPLICATION`), `Size = 0x11b02c`. Contains UI section (`0x90`, `"Odin"`) and PE32+ section (`0xa0`, image at `0xa4`, `1,159,168` bytes = `0x11b000`, SHA-256 `96a77ec846ee258002b721ccb94e629f298862010b8f0890f59940dd0a19f5c8`).
     - PE32+ Sections (`e_lfanew=0xe58`, `Machine=0xaa64`, `Subsystem=10` EFI App, `EntryPoint=0x1000`):
       - `.text`: `0x1000`–`0x78000` (`0x77000`)
       - `.data`: `0x78000`–`0x118000` (`0xa0000`)
       - `.reloc`: `0x118000`–`0x11b000` (`0x3000`)
   - **`LinuxLoader` FFS (`0x11b0a8`–`0x2870e0`)**: GUID `f536d559-459f-48fa-8bbc-43b554ecae8d`, `Type = 0x09` (`EFI_FV_FILETYPE_APPLICATION`), `Size = 0x16c038`. Contains UI section (`0x11b0c0`, `"LinuxLoader"`) and PE32+ section (`0x11b0dc`, image at `0x11b0e0`, `1,490,944` bytes = `0x16c000`, SHA-256 `a67caa9a8d7d4b7f8cfdd5bd847b252b384e77b77bf3c7b770d1366559245b25`).
     - PE32+ Sections (`e_lfanew=0xe58`, `Machine=0xaa64`, `Subsystem=10` EFI App, `EntryPoint=0x1000`):
       - `.text`: `0x1000`–`0x9f000` (`0x9e000`)
       - `.data`: `0x9f000`–`0x169000` (`0xca000`)
       - `.reloc`: `0x169000`–`0x16c000` (`0x3000`)

### 1.3 Cross-Reference with `extracted/xbl_uefiplat.cfg` DDR & Register Map

XBL (`uefiplatLA.cfg`, `DefaultBDSBootApp = "LinuxLoader"`, `DefaultChargerApp = "QcomChargerApp"`) establishes the physical memory and MMIO map before BDS loads `LinuxLoader.efi` from `"ABOOT FV"`:

| Base Address | Size | Label (`xbl_uefiplat.cfg`) | Resource / EFI Memory Type / Cache | Role in ABL Bootflow |
| --- | --- | --- | --- | --- |
| `0x80000000` | `0x05800000` (88 MiB) | `"Kernel"` | `SYS_MEM` / `Reserv` / `WRITE_BACK_XN` | Primary Linux kernel/DTB/ramdisk DDR staging region; `BootLinux` (`0x1db2c`) adds offsets (`\|0x80000` compressed / `\|0x8000` 32-bit, `\|0x5400000` DTB, `\|0x21c00000` ramdisk) to RAM partition base (`FUN_0001c424`). Also note `0x8500000c` BOTA payload staging in `FUN_00019f24`. |
| `0x86000000` | `0x00200000` (2 MiB) | `"SMEM"` | `MEM_RES` / `Reserv` / `UNCACHED_UNBUFFERED_XN` | Shared Memory (`QcomSmemProtocol`); `LinuxLoader` reads SMEM items `0x86` (DDR info) and `0x87` (`hw_rev`). |
| `0x86D00000` | `0x02200000` (34 MiB) | `TzAppsRegnAddr/Size` | TZ Apps region | QSEE/TZ app loading (`bksecapp` loaded via `QcomQseecomProtocol`). |
| `0x94000000` | `0x09400000` (148 MiB) | `"DXE Heap"` | `SYS_MEM` / `Conv` / `WRITE_BACK_XN` | `gBS->AllocatePool` / `AllocatePages` pool used for LZMA decompression, `boot`/`recovery` image loading, and `Odin` 1 MiB RX/TX USB buffers. |
| `0x9D400000` | `0x02400000` (36 MiB) | `"Display Reserved"` | `MEM_RES` / `LdData` / `WRITE_THROUGH_XN` | Framebuffer backing `EfiGraphicsOutputProtocol` and `DisplaySplashBufferInfo` (`/reserved-memory/splash_region` in `0x241a0`). |
| `0x9F800000` | `0x00200000` (2 MiB) | `"FV Region"` | `SYS_MEM` / `BsData` / `WRITE_BACK_XN` | XBL DXE Firmware Volume staging. |
| `0x9FA00000` | `0x00200000` (2 MiB) | `"ABOOT FV"` | `SYS_MEM` / `Reserv` / `WRITE_BACK_XN` | **Load target of `abl.elf` `PHDR[2]` (`Outer FV0`)**; note KASLR metadata writes `_DAT_9fa07000 = 0xcdefcdef` and `_DAT_9fa07004` (`(rand & 0x3f) << 14`) directly into this region in `0x1db2c`! |
| `0x9FC00000` | `0x00300000` (3 MiB) | `"UEFI FD"` | `SYS_MEM` / `BsData` / `WRITE_BACK` | XBL UEFI Flash Device (note `PHDR[1]` MBN hash segment has `paddr=0x9fc00000`). |
| `0x9FFD0000` | `0x00027000` | `"DBI Dump"` | `RtData` (`DBIDumpDDRBase`) | Crash dump buffer. |
| `0x9FFF7000` | `0x00008000` | `"Log Buffer"` | `RtData` | UEFI runtime serial/memory log buffer. |
| `0x146BF000` | `0x00001000` | `"IMEM Cookie Base"` | `MMAP_IO` / `Conv` / `NS_DEVICE` | `SharedIMEMBaseAddr` (`L"Shared_IMEM_Base"` via `gRT->GetVariable`); `+0x1C` MemoryCapture, `+0x24` AbnormalReset, `+0x28` `GCCResetValueAddress`. |
| `0x010A3000` | `0x00001000` | `"MPM2_SLP_CNTR"` | `MMAP_IO` / `MmIO` / `NS_DEVICE` | 32.768 kHz sleep counter (`L"MPM2_SLP_CNTR_ADDR"`) read by `FUN_000272e0` (`BootStats`) and `Odin` `FUN_0001fd78`. |

---

## 2. Entry Point, Library Constructors & Call Tree

Both `LinuxLoader.efi` and `Odin.efi` are compiled against EDK2 `AutoGen.c` with identical entry/constructor/destructor scaffolding at `RVA 0x1000` (`ImageBase = 0x0`).

### 2.1 `_ModuleEntryPoint` (`0x1000`) & Core Global Table

At `0x1000` (`entry(ImageHandle, SystemTable)`):
1. Saves stack canary (`DAT_00156dc0` in `LinuxLoader.efi`, `DAT_00079b90` in `Odin.efi`).
2. Calls `0x10ac` (`ProcessLibraryConstructorList(ImageHandle, SystemTable)`).
3. Calls `0x1574` (`ProcessModuleEntryPointList`), which tail-calls `0x1794` (`LinuxLoaderMain`) in `LinuxLoader.efi` or `0x1dec` (`OdinMain`) in `Odin.efi`.
4. Calls `0x1444` (`ProcessLibraryDestructorList(ImageHandle, SystemTable)`).
5. Verifies the stack canary; on mismatch calls `__stack_chk_fail` (`0x1bc98` in `LinuxLoader.efi`, `0xa28c` in `Odin.efi`).

#### Library Constructor & Destructor Sequence (`0x10ac` & `0x1444`)

| Step | `LinuxLoader.efi` RVA | `Odin.efi` RVA | EDK2 Library Constructor / Destructor | Global(s) Populated / Action |
| --- | --- | --- | --- | --- |
| 1 | `0x37908` | `0x21694` | `UefiBootServicesTableLibConstructor` (`UefiBootServicesTableLib.c`) | Sets `gImageHandle` (`0x167d58` / `0x117630`), `gST` (`0x167d60` / `0x117638`), `gBS = SystemTable->BootServices` (`0x167d68` / `0x117640`) |
| 2 | `0x379f0` | `0x2177c` | `UefiRuntimeServicesTableLibConstructor` (`UefiRuntimeServicesTableLib.c`) | Sets `gRT = SystemTable->RuntimeServices` (`0x167d70` / `0x117648`) |
| 3 | `0x37c78` | `0x21a04` | `BaseDebugLibConstructor` / stub | Returns `0` (`EFI_SUCCESS`) |
| 4 | `0x37dc4` | `0x21b50` | `HobLibConstructor` (`HobLib.c`) | Calls `EfiGetSystemConfigurationTable` (`0x37cb4` / `0x21a40`) with `EfiHobListGuid` -> `gHobList` (`0x167d78` / `0x117650`) |
| 5 | `0x38104` | `0x21e90` | `HiiFrameworkConstructor` | Sets `DAT_00167d84 = 0x80000043` (`gST = SystemTable`) and calls `InstallMultipleProtocolInterfaces(&ImageHandle, &gGuid_EfiHiiFrameworkGuid, &DAT_001577a0 / &DAT_000fc628, NULL)` |
| 6 | `0x38314` | `0x220a0` | `DxeServicesTableLibConstructor` (`DxeServicesTableLib.c`) | Calls `EfiGetSystemConfigurationTable` with `EfiDxeServicesTableGuid` (`05ad34ba-...`) -> `gDS` (`0x167d90` / `0x117668`) |
| 7 | `0x383f0` | `0x2217c` | `ArmArchTimerLibConstructor` (`ArmArchTimerLib.c`) | Verifies ARM Generic Timer (`0x32d58`) and timer frequency (`0x74d50`) |
| 8 | `0x38604` | `0x2230c` | `UefiHiiServicesLibConstructor` (`UefiHiiServicesLib.c`) | Locates `HiiString` (`0x167da0` / `0x117678`), `HiiDatabase` (`0x167db0` / `0x117688`), `HiiConfigRouting` (`0x167db8` / `0x117690`), `HiiFont` (`0x167d98` / `0x117670`), `HiiImage` (`0x167da8` / `0x117680`) |
| Dtor 1 | `0x382c0` | `0x2204c` | `HiiFrameworkDestructor` | Calls `UninstallMultipleProtocolInterfaces(ImageHandle, &gGuid_EfiHiiFrameworkGuid, ...)` |
| Dtor 2 | `0x04664` | `0x0ab28` | `MemoryAllocationLibDestructor` | Walks tracked allocation list (`PTR_LOOP_0009f000` / `PTR_LOOP_00079b98`) and calls `gBS->FreePages` |

### 2.2 `LinuxLoaderMain` (`0x1794`) Top-Level Call Tree

```text
entry (0x1000)
 └─> FUN_000010ac (ProcessLibraryConstructorList)
 └─> FUN_00001574 (ProcessModuleEntryPointList)
      └─> FUN_00001794 (LinuxLoaderMain)
           ├─> FUN_000167f4()                     [Read cached hw_rev from SMEM init]
           ├─> FUN_000272e0(0)                    [BootStats: read Shared_IMEM_Base + MPM2_SLP_CNTR_ADDR]
           ├─> FUN_00005f8c(0x20000)              [Allocate 128 KiB UnsafeStack -> DAT_00157c78]
           ├─> FUN_0001bb94()                     [Initialize stack canary from EfiRngProtocol]
           ├─> FUN_00014b30()                     [Init Glib font "sysfont2x" + line step 0x7d]
           ├─> FUN_0002adac()                     [Platform/chipset early init]
           ├─> FUN_00028890()                     [Device/boot info init]
           ├─> FUN_00027d48()                     [Enumerate GPT/partition entries via PartitionDxe]
           ├─> FUN_00027618(L"boot")              [Check A/B multi-slot support -> FUN_00028e08]
           ├─> FUN_000015ac()                     [Dump BootShutdown History (5 entries from param + RTC)]
           ├─> FUN_0001b280(1, 100, 0)            [Short haptic pulse via SamsungVibratorProtocol]
           ├─> FUN_000158b8()                     [ChargerInit() via SamsungChargerProtocol]
           ├─> FUN_00012a9c()                     [Read MUIC / cable / FG status]
           ├─> FUN_00013cb8()                     [Read PMIC PON/WarmReset/PowerOff reasons (QcomPmicPwrOnProtocol)]
           ├─> FUN_000132e4()                     [[SAPA] RTC / Power-On Alarm validation]
           ├─> FUN_00013b48()                     [CheckDeadBattery (< 3450 mV -> shutdown)]
           ├─> FUN_000173ac()                     [DisplayBltOperationClear (clear screen to black)]
           ├─> FUN_000144a0(2000)                 [Display splash / backlight setup]
           ├─> FUN_00012e10()                     [Boot Mode State Machine: keys, ResetReason, param, Download/Recovery/FOTA]
           ├─> FUN_0001ada0()                     [GPIO test/reset check]
           ├─> [if mode != 2]: FUN_00019f24()     [BOTA bootloader OTA update check/apply -> reboot on completion]
           ├─> [if mode == 6]:                    ["Got Secure Check fail flag from Kernel!" -> red banner + poweroff]
           ├─> FUN_00008860()                     [Load TZ app "bksecapp" via QcomQseecomProtocol]
           │    └─ if < 0: "Fail to load BKSECAPP" -> LAB_00001b34 (Launch Odin)
           ├─> FUN_0000ae5c()                     [Knox / binary / security check]
           │    └─ if == 1: "Re-Download Official system image" -> param=3 -> LAB_00001b34 (Launch Odin)
           ├─> [if mode == 8]:                    ["Carrier Mismatch!" -> red banner + poweroff]
           ├─> [if param.bootingNow == 3]:        ["Download was failed in previous" -> LAB_00001b34 (Launch Odin)]
           ├─> [if mode == 1]:                    [Download Mode: FUN_000152c4() + SUD bitmap FUN_00015458() -> LAB_00001b34]
           │    └─ LAB_00001b34: MuicSetPath(1), ChgSetMaxCurrent(500,1), ChgSetEnCharge(1,0), loop fs0..fs9:Odin -> FUN_0002549c()
           ├─> FUN_00016740()                     [BoardInfo / hw_rev check]
           ├─> FUN_000084b4()                     [KnoxCustom auto-boot-on-power check]
           ├─> FUN_00013464(mode)                 [LPMModeChecker -> returns 1 if entering LPM charger mode]
           ├─> FUN_000138d4()                     [CheckLowBattery (< 3500 mV -> charge loop or poweroff)]
           ├─> FUN_00026e1c(&boot_recovery)       [RecoveryInit: read BCB from "misc" partition]
           ├─> FUN_0001cff4()                     [Board_Init / ChipInfo / PlatformInfo]
           ├─> FUN_00002154(&boot_info)           [Load & verify boot/recovery/dtbo via AVB 2.0]
           ├─> FUN_00006ba4(...)                  [Samsung Sec_Auth_Kernel SignerV2 + TIMA measurement]
           │    └─ if != 0: SCM SIP call 0x2000801 (flags 0..7) via QcomScmProtocol
           ├─> FUN_0000a184(is_recovery, 2)       [Inform TZ of recovery status]
           └─> FUN_0001db2c(&boot_info)           [BootLinux: decompress kernel, select/overlay DTB/DTBO, cmdline, ExitBootServices, jump to kernel]
```

---

## 3. Complete UEFI Protocol & Variable Inventory

> **Note on `extracted/uefi_guids.json` Corrections**: Decompilation of strings and vtable call sites revealed several mislabeled entries in `uefi_guids.json`: `4684800a-...` (labeled `QcomAdcProtocol`) is actually `QcomPmicVersionProtocol`; `8e5eff91-...` (labeled `QcomTokenSpaceGuid_CAF`) is `QcomVerifiedBootProtocol`; `77ed108d-...` is `QcomScmProtocol`; `a74862ce-...` is `QcomQseecomProtocol`; `55b1d734-...` is `EfiHash2Protocol_Qcom`; `f4e5c7d0-...` is `QcomSmemProtocol`; `ad9aec18-...` is `QcomTlmmProtocol`; `fe2555be-...` is `EfiPartitionRecordProtocol`; `6848de61-...` is `EfiPartitionTypeGuidProtocol`; `5172ffb5-...` is `QcomRamPartitionProtocol`; `f57f73ed-...` is `QcomKernelModeSwitchProtocol`; `d35dc019-...` is `QcomEmmcWpProtocol`; `ae1cdd2b-...` is `QcomStorageWpProtocol`; `1e28a9ba-...` is `QcomEmmcPonProtocol`; `8b0d8671-...` is `QcomUfsSsuProtocol`; `8f644fa9-...` is `EfiFirmwareVolumeBlock2Protocol`; `56ec3091-...` is `EfiLoadFileProtocol`; and `a77b2472-...` (`bbc1` typo in JSON vs `bcc1` in `Odin.efi`) is `EfiBlockIo2Protocol`.

### 3.1 UEFI Protocols & Services Consumed

| GUID String | Resolved Name | XBL DXE Owner | `LinuxLoader.efi` `.rodata` RVA | `Odin.efi` `.rodata` RVA | Vtable Offsets / Methods Called | Calling Functions (RVA) |
| --- | --- | --- | --- | --- | --- | --- |
| `9042a9de-23dc-4a38-96fb-7aded080516a` | `EfiGraphicsOutputProtocol` | `DisplayDxe` / `GraphicsConsoleDxe` | `0x7be54`, `0x9ebf4` (+stack) | `0x5c0d8`, `0x77f50` (+stack) | `+0x00` `QueryMode`, `+0x08` `SetMode`, `+0x10` `Blt`, `+0x18` `Mode` | LL: `0x1486c`, `0x17134`, `0x173ac`, `0x174ec`, `0x17a64`, `0x17dcc`; Odin: `0x1aa10`, `0x1bd0c`, `0x1bf84`, `0x1c0c4`, `0x1c63c` |
| `e9ca4775-8657-47fc-97e7-7ed65a084324` | `EfiHiiFontProtocol` | `FontDxe` / `HiiDatabase` | `0x9ec04` | `0x77f60` | `+0x00` `StringToImage` | LL: `0x38604` (ctor), `0x1486c`; Odin: `0x2230c` (ctor), `0x1aa10` |
| `0fd96974-23aa-4cdc-b9cb-98d17750322a` | `EfiHiiStringProtocol` | `HiiDatabase` | `0x9ec24` | `0x77f80` | Cached by `UefiHiiServicesLib` | LL: `0x38604`; Odin: `0x2230c` |
| `ef9fc172-a1b2-4693-b327-6d32fc416042` | `EfiHiiDatabaseProtocol` | `HiiDatabase` | `0x9ec44` | `0x77fa0` | Cached by `UefiHiiServicesLib` | LL: `0x38604`; Odin: `0x2230c` |
| `587e72d7-cc50-4f79-8209-ca291fc1a10f` | `EfiHiiConfigRoutingProtocol` | `HiiDatabase` | `0x9ec54` | `0x77fb0` | Cached by `UefiHiiServicesLib` | LL: `0x38604`; Odin: `0x2230c` |
| `31a6406a-6bdf-4e46-b2a2-ebaa89c40920` | `EfiHiiImageProtocol` | `HiiDatabase` | `0x9ec34` | `0x77f90` | Cached by `UefiHiiServicesLib` | LL: `0x38604`; Odin: `0x2230c` |
| `4c8a2451-c207-405b-9694-99ea13251341` | `EfiHiiFrameworkGuid` | `AutoGen.c` (self-installed) | `0x9ec14` | `0x77f70` | `InstallMultipleProtocolInterfaces` / `UninstallMultipleProtocolInterfaces` | LL: `0x38104`, `0x382c0`; Odin: `0x21e90`, `0x2204c` |
| `dd9e7534-7762-4698-8c14-f58517a625aa` | `EfiSimpleTextInputExProtocol` | `ButtonsDxe` / `ConSplitterDxe` | `0x9e994` | `0x77ed0` | `+0x00` `Reset`, `+0x08` `ReadKeyStrokeEx` (`OpenProtocol` on `gST->ConsoleInHandle`) | LL: `0x26c20`; Odin: `0x1fb7c` |
| `964e5b21-6459-11d2-8e39-00a0c969723b` | `EfiBlockIoProtocol` | `UFSDxe` / `SdccDxe` | `0x9e9a4` | `0x77df0` | `+0x08` `Media`, `+0x18` `ReadBlocks`, `+0x20` `WriteBlocks` | LL: `0x24d28`, `0x3bce0`, `0x3c1ac`, `0x18388`, `0x19f24`; Odin: `0x068c0`, `0x1f42c` |
| `a77b2472-e282-4e9f-a245-c2c0e27bbcc1` | `EfiBlockIo2Protocol` | `UFSDxe` / `SdccDxe` | — | `0x77e00` | `+0x00` `Media`, `+0x18` `WriteBlocksEx` (`local_60[3]`) + `WaitForEvent` | Odin: `0x03348` |
| `fe2555be-d716-4686-b9d0-79db5921b70d` | `EfiPartitionRecordProtocol` | `PartitionDxe` | `0x9ea44` | `0x77e10` | Struct fields: `+0x20` `StartingLBA`, `+0x38` `PartitionName` (UTF-16) | LL: `0x181b0`, `0x24d28`, `0x27d48`, `0x6f444`; Odin: `0x03348`, `0x1ca58`, `0x1cc58`, `0x1f42c`, `0x1ff4c` |
| `6848de61-eb61-4def-9a8e-3817cbeb8f1c` | `EfiPartitionTypeGuidProtocol` | `PartitionDxe` | `0x9e824` | `0x77d90` | 16-byte GPT Partition Type GUID handle attachment | LL: `0x24d28`; Odin: `0x1f42c` |
| `85c1f7d2-bce6-4f31-8f4d-d37e03d05eaa` | `EfiMemCardInfoProtocol` | `UFSDxe` / `SdccDxe` | `0x9ea34` | `0x77e20` | `+0x08` `GetCardInfo`, `+0x10` `GetBootLun`, `+0x18` `SetBootLun` | LL: `0x1c734`, `0x1d314`, `0x1d4e0`; Odin: `0x068c0`, `0x1ecb4`, `0x1f118` |
| `95a9a93e-a86e-4926-aaef-9918e772d987` | `EfiEraseBlockProtocol` | `UFSDxe` / `SdccDxe` | `0x9ea74` | `0x77e30` | `+0x10` `EraseBlocks` + `WaitForEvent` | LL: `0x25998`; Odin: `0x1f9b0` |
| `09576e91-6d3f-11d2-8e39-00a0c969723b` | `EfiDevicePathProtocol` | `DevicePathDxe` | `0x9e9c4` | `0x77e90` | Device path node inspection (`BlockIo` / `LoadedImage`) | LL: `0x24d28`, `0x2ed28`, `0x3c7ac`; Odin: `0x1f42c` |
| `5b1b31a1-9562-11d2-8e3f-00a0c969723b` | `EfiLoadedImageProtocol` | `DxeCore` | `0x9e9b4` | — | `+0x30` `LoadOptionsSize`, `+0x38` `LoadOptions` (on `Odin` image handle) | LL: `0x2549c` |
| `964e5b22-6459-11d2-8e39-00a0c969723b` | `EfiSimpleFileSystemProtocol` | `Fat` / `FvSimpleFileSystem` | `0x9e9d4` | `0x77ee0` | `+0x08` `OpenVolume` (`fs0..fs9:` resolution for `fs%d:Odin`) | LL: `0x24d28`, `0x3bce0`, `0x3c1ac`; Odin: `0x1f42c` |
| `ce345171-ba0b-11d2-8e4f-00a0c969723b` | `EfiDiskIoProtocol` | `DiskIoDxe` | `0x9e9f4` | — | `+0x08` `ReadDisk` | LL: `0x3ce40` |
| `56ec3091-954c-11d2-8e3f-00a0c969723b` | `EfiLoadFileProtocol` | `DxeCore` / `QcomBds` | `0x9e9e4` | — | `LocateHandleBuffer` + `HandleProtocol` | LL: `0x3bce0`, `0x3c7ac` |
| `220e73b6-6bdb-4413-8405-b974b108619a` | `EfiFirmwareVolume2Protocol` | `DxeCore` | `0x9ec74` | — | `+0x18` `ReadSection`, `+0x28` `GetNextFile` | LL: `0x3bce0`, `0x3c53c` |
| `8f644fa9-e850-4db1-9ce2-0b44698e8da4` | `EfiFirmwareVolumeBlock2Protocol` | `DxeCore` | `0x9ec84` | — | `+0x10` `GetBlockSize`, `+0x18` `GetPhysicalAddress`/Blocks | LL: `0x3c53c` |
| `03c4e603-ac28-11d3-9a2d-0090273fc14d` | `EfiDebugPortProtocol` | `DxeCore` / `SimpleTextInOutSerial` | `0x9ec64` | — | `+0x08`, `+0x28` | LL: `0x74de4`, `0x74e88` |
| `3152bca5-eade-433d-862e-c01cdc291f44` | `EfiRngProtocol` | `RngDxe` | `0x9ea64` | `0x77e70` | `+0x00` `GetInfo`, `+0x08` `GetRNG` (stack canary + KASLR seed) | LL: `0x1bb94`, `0x1d9f4`; Odin: `0x0a188` |
| `d2b2b828-0826-48a7-b3df-983c006024f0` | `EfiReportStatusCodeProtocol` | `ReportStatusCodeRouterRuntimeDxe` | `0x9ea84` | `0x77e80` | Status code reporting (`DEBUG()` macro) | LL: `0x3d488`; Odin: `0x22634` |
| `59d1c24f-50f1-401a-b101-f33e0daed443` | `EfiStatusCodeRuntimeProtocol` | `StatusCodeHandlerRuntimeDxe` | `0x9e964` | `0x77dd0` | Runtime status code table ref | LL `.rodata`; Odin `.rodata` |
| `b0760469-970c-487a-a4b5-28db7b45cef1` | `QcomChipInfoProtocol` | `ChipInfo` | `0x9ea14` | `0x77ef0` | `+0x08` `GetChipVersion`, `+0x18` `GetChipId`, `+0x28` `GetChipIdString`, `+0x48` `GetSerialNumber`, `+0x50` `GetFoundryId` | LL: `0x16874`, `0x1cff4`, `0x1d878`, `0x2b914`; Odin: `0x1b688`, `0x1f38c` |
| `157a5c45-21b2-43c5-ba7c-822fee5fe599` | `QcomPlatformInfoProtocol` | `PlatformInfoDxeDriver` | `0x9ea04` | — | `+0x08` `GetPlatformInfo` | LL: `0x1cff4` |
| `4684800a-2755-4edc-b443-7f8ceb3239d3` | `QcomPmicVersionProtocol` | `PmicDxe` | `0x9ea24` | `0x77f00` | `+0x00` rev, `+0x08` `GetPmicInfo`, `+0x10` `GetPmicInfoExt` | LL: `0x16874`, `0x1cdec`, `0x1ccf0`; Odin: `0x1b688` |
| `97044b58-fea4-4ad0-9d0b-e417d60f11a1` | `QcomPmicPwrOnProtocol` | `PmicDxe` | `0x9eb84` | — | `+0x18` `GetPonReason`, `+0x20` `WarmResetStatus`, `+0x28` `GetAllPonReasons` | LL: `0x13cb8`, `0x260b4` |
| `fcbedc3e-d2a6-4234-9be5-c5ea93d1f392` | `QcomPmicRtcProtocol` | `PmicDxe` / `RealTimeClock` | `0x9eb24` | — | `+0x30` `GetTimeValue`, `+0x50` `GetAlarmValue`, `+0x60` `AlarmEnable` | LL: `0x19e84`, `0x19b5c`, `0x19c20`, `0x19da8` |
| `a022155a-4828-4535-a499-11f15240b91b` | `QcomResetReasonProtocol` | `ResetRuntimeDxe` | `0x9ea54` | — | `+0x08` `GetResetReason`, `+0x10` `ClearResetReason` (when rev > `0x10001`) | LL: `0x12b9c` |
| `6edc8a6d-2663-43cd-90ff-4621ffd10df5` | `QcomChargerProtocol` | `QcomChargerApp` / `Chg` | `0x9eb94` | — | `+0x00` rev, `+0x08` `GetChargerPresence`, `+0x20` `IsOffModeCharging` | LL: `0x260b4` |
| `f4e5c7d0-d239-47cb-aacd-7f66ef763238` | `QcomSmemProtocol` | `SmemDxe` | `0x9eb34` | `0x77f10` | `+0x10` `SmemGetAddr` (SMEM ID `0x86` DDR info, `0x87` `hw_rev`) | LL: `0x16554`, `0x16650`; Odin: `0x1b1cc` |
| `ad9aec18-7bf0-4809-9e96-3012309f3df7` | `QcomTlmmProtocol` | `DALTLMM` | `0x9eb54` | — | `+0x08` `ConfigGpio`, `+0x18` `GpioIn` | LL: `0x1b978`, `0x1baa8` |
| `5172ffb5-4253-7d51-c641-a701f973103c` | `QcomRamPartitionProtocol` | `EnvDxe` | `0x9eb04` | — | `+0x18` `GetRamPartitions`, `+0x20` `GetMinPasrSize` | LL: `0x1c154`, `0x1c2f8` |
| `f57f73ed-0afc-4723-9374-2cebc0198ef9` | `QcomKernelModeSwitchProtocol` | `EnvDxe` | `0x9ebb4` | — | `+0x00` `SwitchTo32BitMode` | LL: `0x1db2c` |
| `77ed108d-8524-4b8b-9d2e-34987aecb9c1` | `QcomScmProtocol` | `TzDxe` | `0x9ead4` | — | `+0x38` `ScmSipSysCall` (SMC `0x2000801` + `MP_DATA`) | LL: `0x01794`, `0x2b238` |
| `a74862ce-680f-4fe1-a311-df41f4030391` | `QcomQseecomProtocol` | `TzDxe` | `0x9ea94` | `0x77e40` | `+0x08` `QseecomStartApp("bksecapp")`, `+0x18` `QseecomSendCmd` | LL: `0x08860`, `0x08994`; Odin: `0x10508`, `0x1063c` |
| `55b1d734-c5e1-49db-9647-b16afb0e305b` | `EfiHash2Protocol_Qcom` | `HashDxe` | `0x9eaa4` | `0x77e50` | `+0x08` `Hash`, `+0x10` `HashInit`, `+0x18` `HashUpdate`, `+0x20` `HashFinal` | LL: `0x06ba4`, `0x08dc8`, `0x6e7c8`, `0x6f124`, `0x6f324`; Odin: `0x0e3bc`, `0x0ed18`, `0x0ef18` |
| `8e5eff91-21b6-47d3-af2b-c15a01e020ec` | `QcomVerifiedBootProtocol` | `VerifiedBootDxe` | `0x9eba4` | `0x77f20` | `+0x14` `VBRwDeviceState` / AVB ops, `+0x30` `VBDeviceResetState` | LL: `0x02154`, `0x25698`, `0x258b8`; Odin: `0x1f8c0` |
| `ae1cdd2b-b59a-413a-8dff-56d2fc63b7e0` | `QcomStorageWpProtocol` | `UFSDxe` | `0x9eae4` | `0x77eb0` | Write-protect handle (`DAT_00168e58` / `DAT_0010c160`) | LL: `0x70598`; Odin: `0x143d4` |
| `d35dc019-3eab-4655-ba9a-734a8d8b9847` | `QcomEmmcWpProtocol` | `SdccDxe` | `0x9eaf4` | `0x77ec0` | `+0x10` `SetWriteProtect`, `+0x18` `GetWriteProtectType` | LL: `0x70598`, `0x6f444`; Odin: `0x143d4` |
| `1e28a9ba-54b1-4a93-9b45-56c8b4daa55c` | `QcomEmmcPonProtocol` | `SdccDxe` | `0x9ebc4` | `0x77f30` | `+0x08` `PowerOffNotify(3)` (eMMC long power-off notify) | LL: `0x1be88`; Odin: `0x1e998` |
| `8b0d8671-f542-4ee8-a70c-95f5524ae117` | `QcomUfsSsuProtocol` | `UFSDxe` | `0x9ebd4` | `0x77f40` | `+0x08` `SendSSU(3)` (UFS Start/Stop Unit power down) | LL: `0x1be88`; Odin: `0x1e998` |
| `d68edce2-a314-457b-962a-1d99bbfcbbfb` | `QcomNandPartiGuidProtocol` | `PartitionDxe` / Nand | `0x9ebe4` | — | `+0x08` `GenGuid(L"misc", ...)` | LL: `0x25790` |
| `2cc73155-a1f9-4c4b-88e2-caf9390e126a` | `SamsungMuicProtocol` | `Muic` (Samsung XBL DXE) | `0x9eb14` | — | `+0x08` `GetDeviceType` / `GetJigType`, `+0x10` `SetPath` | LL: `0x156cc`, `0x157a8`, `0x15984` |
| `3c7596fa-0058-4496-a648-6d14be4023b2` | `SamsungChargerProtocol` | `Chg` (Samsung XBL DXE) | `0x9eb44` | — | `+0x10` `SetChgCurrentByType`, `+0x18` `SetMaxCurrent`, `+0x20` `SetEnCharge`, `+0x28` `SetChgReconfig`, `+0x38` `GetChargerStatus`, `+0x58` `ChargerInit`, `+0x60` `FgGetVoltage`, `+0x68` `FgGetSoc`, `+0x70` `FgGetFgReset`, `+0x78` `GetBattTemp`, `+0x80` `FgCheckModelData`, `+0x88` `FuelgaugeInit` | LL: `0x158b8`, `0x15aac`–`0x16488` |
| `6c3dbb2c-4354-4f5a-9e2f-40658db24402` | `SamsungNpaLdoProtocol` | `NpaLdo` (Samsung XBL DXE) | `0x9eb64` | — | `+0x00` `InitNpaLdo6`, `+0x08` `SetNpaLdo6` | LL: `0x1afa4`, `0x1b07c` |
| `aa2e776d-8c9c-4268-998a-8b0a13bf0501` | `SamsungVibratorProtocol` | `Vib` (Samsung XBL DXE) | `0x9eb74` | — | `+0x00` `InitVib`, `+0x08` `SetVib` | LL: `0x1b280` |
| `d9d9ce48-44b8-494f-8e3e-2a3b927dc6c1` | `QcomUsbDeviceProtocol` | `UsbDeviceDxe` | — | Stack (`0x1634`) | `+0x20` `AllocateTransferBuffer` (`1 MiB` RX/TX), `+0x28` `FreeTransferBuffer`, `+0x48` `Start` (with `DAT_000fc978` descriptors) | Odin: `0x01634`, `0x01dec` |
| `1c0cffce-fc8d-4e44-8c78-9c9e5b530d36` | `QcomUsbInitEventGuid` | `UsbConfigDxe` | — | Stack (`0x1634`) | `gBS->CreateEventEx` + `SignalEvent` + `CloseEvent` to wake USB controller | Odin: `0x01634` |

### 3.2 Auxiliary / Configuration / DevicePath / Hash Algorithm GUIDs

| GUID String | Name | `LinuxLoader` RVA | `Odin` RVA | Purpose |
| --- | --- | --- | --- | --- |
| `7739f24c-93d7-11d4-9a3a-0090273fc14d` | `EfiHobListGuid` | `0x9e954` | `0x77dc0` | `HobLibConstructor` (`0x37dc4` / `0x21b50`) |
| `05ad34ba-6f02-4214-952e-4da0398e2bb9` | `EfiDxeServicesTableGuid` | `0x9e974` | `0x77de0` | `DxeServicesTableLibConstructor` (`0x38314` / `0x220a0`) |
| `09576e92-6d3f-11d2-8e39-00a0c969723b` | `EfiFileInfoId` | `0x9e804` | — | `EFI_FILE_PROTOCOL.GetInfo` in `0x3c1ac` |
| `09576e93-6d3f-11d2-8e39-00a0c969723b` | `EfiFileSystemVolumeLabelId` | `0x9e814` | — | Volume label query in `0x3bce0` |
| `9a4e9246-d553-11d5-87e2-00062945c3b9` | `EfiPrintLibGuid` | `0x9e914` | `0x77d80` | `DebugLib.c` `ReportStatusCodeWithExtendedData` caller/data GUID (`0x2ee70` / `0x1e3f0`) |
| `335984bd-e805-409a-b8f8-d27ece5ff7a6` | `EfiMemoryTypeInformationGuid` | `0x9e904` | `0x77d70` | Default `DataGuid` fallback in `ReportStatusCodeLib.c` (`0x3d6f8` / `0x228a4`) |
| `f536d559-459f-48fa-8bbc-43b554ecae8d` | `SamsungLinuxLoaderAppGuid` | `0x9e7f4` | — | Default `CallerId` in `ReportStatusCodeLib.c` (`0x3d6f8`) |
| `aba3b456-5469-414a-9f79-47cecbd7c04e` | `SamsungOdinAppGuid` | — | `0x77cd0` | Default `CallerId` in `ReportStatusCodeLib.c` (`0x228a4`) |
| `51aa59de-fdf2-4ea3-bc63-875fb7842ee9` | `EfiHashAlgorithmSha256Guid` | `0x9eab4` | `0x77e60` | Passed to `EfiHash2Protocol_Qcom` `Hash` / `HashInit` |
| `2ae9d80f-3fb2-4095-b7b1-e93157b946b6` | `EfiHashAlgorithmSha1OrSec2Guid` | `0x9eac4` | `0x77ea0` | Passed to `EfiHash2Protocol_Qcom` `HashInit` (`0x6f124` / `0x0ed18`) |
| `ebd0a0a2-b9e5-4433-87c0-68b6b72699c7` | `EfiPartitionTypeBasicData` | — | `0x78aa4` | Basic Data GPT Partition Type GUID (`Odin`) |
| `82acc91f-4a68-357c-9e68-8f9c-a1231a1b` | `MiscPartitionTypeGuid_Local` | Stack (`0x26e1c`) | — | Default `misc` partition type GUID for `FUN_00026fc4` |
| `4ba1d05f-...`, `4acf98f6-...`, `8598155f-...` | `QcomSdccUfsGuid_{4ba1,4acf,8598}` | `0x9e8c4`–`0x9e8e4` | `0x77d30`–`0x77d50` | SDCC/UFS partition/LUN GUID constants in `FUN_00027fa0` / `FUN_000201a4` |
| `b615f1f5-...`..`d33f1985-...` (9 GUIDs) | `QcomUfsLu` / `Emmc` / `Nand` Root Vendor GUIDs | `0x9e834`–`0x9e8b4` | `0x77ce0`–`0x77d20` | Storage root device-path filters in `FUN_0001c734` (`0x9e834` eMMC, `0x9e874` UFS, `0x9e844` NAND) and `Odin` `FUN_0001ecb4` |

### 3.3 UEFI Runtime Variables (`gRT->GetVariable`, Namespace `QcomTokenSpaceGuid` `882f8c2b-9646-435f-8de5-f208ff80c1bd`)

Neither `LinuxLoader.efi` nor `Odin.efi` calls `gRT->SetVariable`. All `gRT->GetVariable` calls query `QcomTokenSpaceGuid` (`0x9e8f4` in `LinuxLoader`, `0x77d60` in `Odin`):

| Variable Name (UTF-16LE) | String RVA (`LL` / `Odin`) | Calling Function(s) | Data Read / Purpose |
| --- | --- | --- | --- |
| `L"DisplayPanelConfiguration"` | `0x7b7f8` / — | LL `0x16ef8` (`GlibGetBgColorByCmdLine`), `0x260b4` (`UpdateCmdLine`) | Panel config string (`"lcd_id=0x..."`, `msm_drm.dsi_display0=...`) appended to kernel cmdline (`DAT_0015d040`). |
| `L"DisplaySplashBufferInfo"` | `0x7f900` / — | LL `0x241a0` (`UpdateDeviceTree`) | Splash framebuffer `{Version, Addr, Size}` (`DAT_0015d024`) patched into `/reserved-memory/splash_region`. |
| `L"BootDeviceBaseAddr"` | `0x7fdc2` / — | LL `0x25b64` (`GetBootDeviceName`) | MMIO base of UFS/eMMC controller formatted into `androidboot.bootdevice=%x.ufshc` or `%x.sdhci`. |
| `L"Shared_IMEM_Base"` | `0x8046a` / `0x5d290` | LL `0x272e0`, Odin `0x1fd78` | Shared IMEM physical base (`0x146BF000`, cached at `DAT_0015d140` / `DAT_0010d3d0`) for BootStats. |
| `L"MPM2_SLP_CNTR_ADDR"` | `0x8048c` / `0x5d2b2` | LL `0x272e0`, Odin `0x1fd78` | MPM2 sleep counter MMIO address (`0x010A3000`, cached at `DAT_0015d148` / `DAT_0010d3d8`) for BootStats. |

---

## 4. Boot Mode & Reboot Reason State Machine

`LinuxLoaderMain` (`0x1794`) determines the boot path through a multi-stage hardware + persistent-state state machine:

### 4.1 Stage 1: PMIC Power-On, Warm Reset & RTC Alarm (`0x13cb8`, `0x132e4`, `0x13b48`)

1. **`FUN_00013cb8` (`0x13cb8`)**: Locates `QcomPmicPwrOnProtocol` (`0x9eb84`):
   - `+0x18` (`GetPonReason(0, &DAT_00158238)`): bitmask of PON triggers (`bit 0` = `KPDPWR`/hard power button, `bit 3/4` = DC/USB charger, `bit 6` = cable, `bit 7` = PON1/other; `(char)DAT_00158238 < 0` checked in LPM).
   - `+0x28` (`GetAllPonReasons(0, &DAT_00158248)`): logs `PowerOnReason`, `WarmResetReason`, `PowerOffReason`, `OffReason`, `BootType` (`HardReset[O/X]`, `SMPL`, `DC_CHG`, `USB_CHG`, `PON1`, `Cable`, `PS_HOLD`, `PMIC_WD`, `KPDPWR_N_RESIN`, `RAW_XVDD_SHD`, `POFF_SEQ`, `S3_RESET`).
   - `+0x20` (`WarmResetStatus(0, &local_4c)`): sets `DAT_0015823c = (local_4c == 0)` (cold boot flag).
2. **`FUN_000132e4` (`0x132e4`) — `[SAPA]` Power-On Alarm**: Reads RTC (`0x19b5c`) and Alarm (`0x19c20`) via `QcomPmicRtcProtocol`. If `DAT_00158238 & 0x4` (RTC alarm PON) and `alarm` is outside `[rtc, rtc+300]` while `param.bootingNow == 0` and `ResetReason == 0`, clears alarm (`0x19da8`) and shuts down (`FUN_0001c0a8("PowerOnAlarmChecker", 0x24b)`).
3. **`FUN_00013b48` (`0x13b48`) — `CheckDeadBattery`**: Skipped for `"VZW"` sales code (`0x19404`). Otherwise reads `vcell` (`0x15f2c`), `cable_type` (`0x15e1c`), `jig` (`0x15984`). If `jig == 0`, `(PON & 1) == 0`, `cable == 0`, and `vcell < 3450` mV (`0xd7a`), disables alarm and powers off (`FUN_0001c0a8("CheckDeadBattery", 0x37d)`).

### 4.2 Stage 2: Keys, `QcomResetReasonProtocol`, & `param` (`FUN_00012e10` @ `0x12e10` + `FUN_00012b9c` @ `0x12b9c`)

`FUN_00012e10` returns an integer boot mode (`0`=Normal, `1`=Download/Odin, `2`=Recovery, `4`=FOTA, `6`=Modem Secure Check Fail, `8`=Carrier Mismatch):

1. **`param` Initialization (`0x1914c` -> `0x1991c`)**: Reads `param` partition (`FUN_00018388` at `0x18388`, `4096`-byte block at offset `0` for `type=0`, or `(total_blocks+1) - (0x1000/blk_sz)*0x100` for `type=1`, or `*1` for `type=3`). If debug level is `0`, initializes `param`.
2. **Hardware Key Combos (`0x26c20`)**: Opens `EfiSimpleTextInputExProtocol` (`ButtonsDxe`) on `gST->ConsoleInHandle`, calls `ReadKeyStrokeEx` (`local_40[1]`) and `Reset` (`local_40[0]`). Returns `ScanCode` in `*param_1` (`local_2c`):
   - `0x21` / `0xa1` (VolUp + Power, etc.): If `param.bootingNow == 3` (`PARAM_BOOT_DOWNLOAD_FAIL`), returns `1` (Odin); else clears `param` (`0x19da8(0,0)`) and returns `2` (`[KEY] Recovery Mode, Reset param!`).
   - `0x02` / `0x22` / `0x82` / `0xa2` (VolDown combos): Checks `DAT_00158228` (MUIC/cable state from `0x12a9c`, `DAT_00158228 - 1 < 2` means USB/JIG connected). If connected, displays warning screen (`FUN_00014ef8`), waits for release then key confirmation (`1`=continue to Download Mode `1`, `2`=cancel/reboot/recovery).
3. **`QcomResetReasonProtocol` (`FUN_00012b9c` @ `0x12b9c`)**: Locates `QcomResetReasonProtocol` (`0x9ea54`), reads `DAT_00158234` via `+0x08` and clears it via `+0x10`:
   - `0x00`: Normal (`0`)
   - `0x01`: Recovery (`2`) — `FUN_00012e10` clears `param` (`0x1991c`, `0x19da8`), writes `param.bootingNow = 2` (`0x186f8(2)`)
   - `0x02`: Writes `param.sud_flag = 0x100` (`0x19684`), returns `1` (Download)
   - `0x03`: Returns `5`
   - `0x14`: If `param.bootingNow` is `4` or `2`, resets `param.bootingNow = 0` (`0x186f8(0)`), returns `0`
   - `0x15`: Writes `0x10000` (`0x19684`), returns `1` (Download)
   - `0x1a`: Returns `6` (`Got Secure Check fail flag from Kernel!`)
   - `0x20`–`0x2a`: `SUD` download mode `(reason & 0xf) + 1`, writes `0x19684`, returns `1` (Download)
   - `0x2c`: Returns `8` (`Carrier Mismatch!`)
   - `0x30` / `0x31` / `0x32`: Sets debug level (`0x4f4c` LOW / `0x494d` MID / `0x4948` HIGH) via `0x18d58`, and `0x31` enables `Force Upload` (`5`) via `0x18b28`
   - `0x33` / `0x34`: Sets `0x5500` / `0x55ff` in `param` (`0x19020`)
   - `0x35` / `0x36` / `0x3e` / `0x3f`: Sets `0x4350` (`CP`) / `0` / `0x4d42` (`BM`) in `param` (`0x19570`)
   - `0x48` / `0x49`: `Force Upload : ON` (`5`) / `OFF` (`0`) via `0x18b28`
4. **SMPL / Cold-Boot Download Fallback & `param.bootingNow`**:
   - If `DAT_00158228 == 6` and `(DAT_00158238 & 1) == 0` and `DAT_0015823c != 0`: returns `1` (Download).
   - Otherwise switches on `param.bootingNow` (`0x18338`): `0` = `PARAM_BOOT_CHARGING` (`0`), `2` = `PARAM_BOOT_RECOVERY_ENTER` (`2`), `3` = `PARAM_BOOT_DOWNLOAD_FAIL` (`1`), `4` = `PARAM_BOOT_FOTA_ENTER` (`4`).

### 4.3 Stage 3: LPM Charger, Low Battery, BCB (`misc`), & Dispatch (`0x1794`)

- **Download Mode (`mode == 1`, `bksecapp` load failure, `ae5c == 1`, or `param.bootingNow == 3`) -> `LAB_00001b34`**:
  - Draws Download Mode / SUD splash (`FUN_000152c4`, `FUN_00015458`), switches MUIC path (`0x157a8(1)`), configures charger (`0x15b88(500, 1)`, `0x15c6c(1, 0)`), and loops `i = 0..9` formatting `"fs%d:Odin"` (`0x04814`) and calling `FUN_0002549c(1, &local_80)`.
  - `FUN_0002549c` (`0x2549c`) resolves the path via `FUN_0003c7ac` (`0x3c7ac`, iterating `EfiSimpleFileSystemProtocol` handles cached by `FUN_0003bce0`), reads the image into memory (`FUN_0003d30c`) or uses its `DevicePath`, calls `gBS->LoadImage(0, gImageHandle, ...)` and `gBS->StartImage(...)`, transferring control to `Odin.efi` (`0x1000` -> `0x1dec`).
- **LPM / Off-Mode Charging (`FUN_00013464` @ `0x13464`)**:
  - Skipped if `FUN_000084b4()` (`[KnoxCustom] Auto boot on power enabled`) returns `1` and `eng`/`user` check passes.
  - Otherwise checks PON (`DAT_00158238`), MUIC `jig` (`0x15984`), `mode != 2`, and `ChgGetChargerStatus` (`0x15e1c`). If powered by charger without power key/jig (`cable != 0` and `(PON & 1) == 0`), disables charging until `vcell >= 3100` mV (`0xc1c`) in a 1 s polling loop, checks battery model (`0x16360`), and returns `1` (`DAT_00158478 = 1`), which causes `UpdateCmdLine` (`0x260b4`) to append `androidboot.mode=charger androidboot.baseband=lpm`.
- **Low Battery Check (`FUN_000138d4` @ `0x138d4`)**: If `jig == 0`, `(PON & 1) == 0`, `cable != 0`, and `vcell < 3500` mV (`0xdac`), charges in a 1 s loop until `>= 3500` mV (or powers off if USB/WC removed).
- **`RecoveryInit` (`FUN_00026e1c` @ `0x26e1c`) & `BootLinux` (`0x1db2c`)**:
  - Reads `misc` partition BCB (`0x26fc4`); if command starts with `"boot-recovery"` (`0x75df4`), sets `local_564[0] = 1` (`"Booting Into Recovery Mode\n"`). Also enters Recovery if `mode == 2`. Otherwise sets `local_564[0] = 0` (`"Booting Into Mission Mode\n"`).
  - `BootLinux` (`0x1db2c`) selects `"recovery"` when `*param_1 == '\0' && param_1[1] != '\0'` (i.e. `is_recovery == 1` and non-empty check), otherwise `"boot"`.
- **Shutdown / Reboot (`ShutdownServices.c` `0x1c0a8`, `0x1be88`)**:
  - `FUN_0001c0a8` reads RTC (`0x19b5c`), logs caller/line (`0x19734`), and invokes `gRT->ResetSystem(EfiResetShutdown=2, EFI_ABORTED, 0, NULL)`.
  - `FUN_0001be88` notifies eMMC (`QcomEmmcPonProtocol` `+0x08`) or UFS (`QcomUfsSsuProtocol` `+0x08`) power-down and invokes `gRT->ResetSystem(EfiResetCold=0, ..., L"RESET_PARAM")` (or `EfiResetPlatformSpecific=3` for `param_1 == -1`).

---

## 5. Hardware, Board & Display Initialization

### 5.1 Samsung `BoardInfo.c`, `Board.c`, SMEM, ChipInfo & PMIC Revision

- **SMEM DDR & `hw_rev` (`BoardInfo.c`)**:
  - `FUN_00016554` (`0x16554`): Locates `QcomSmemProtocol` (`0x9eb34`), calls `+0x10` (`SmemGetAddr(0x86, &size, &addr)`), copies `0x60` bytes of DDR vendor/geometry info (`DDR VERNDOR : %a` in `0x16874`).
  - `FUN_00016650` (`0x16650`): Calls `SmemGetAddr(0x87, &size, &addr)` and stores `*(uint64_t *)(addr + 0x10)` as 32-bit `hw_rev` in `DAT_00156db8`, read via `FUN_000167f4` (`0x167f4`) and asserted in `FUN_00016740` (`0x16740`).
- **SoC & Platform Identification (`Board.c` / `0x1cff4`)**:
  - `FUN_0001cff4` (`0x1cff4`): Locates `QcomChipInfoProtocol` (`0x9ea14`) and invokes `+0x18` (`GetChipId` -> `DAT_0015cfe8`), `+0x08` (`GetChipVersion` -> `DAT_0015cffc`), `+0x50` (`GetFoundryId` -> `DAT_0015d000`), `+0x28` (`GetChipIdString`, 16 bytes -> `DAT_0015cfec`), `+0x48` (`GetSerialNumber` -> `DAT_0015d004`, also via `0x1d878`). Then locates `QcomPlatformInfoProtocol` (`0x9ea04`) and calls `+0x08` (`GetPlatformInfo` -> `DAT_0015cfd8`, validated `< 0x23`).
- **PMIC Model / Target (`Board.c` `0x1cc0c`, `0x1cdec`, `0x1ccf0`)**:
  - `FUN_0001ccf0` (`0x1ccf0`): Locates `QcomPmicVersionProtocol` (`0x9ea24`, PM660) and calls `local_40[1]` (`+0x08`, `GetPmicInfo(pmic_idx, &info)`).
  - `FUN_0001cdec` (`0x1cdec`): If protocol revision `>= 0x10003`, calls `*(local_30 + 0x10)` (`GetPmicInfoExt`) to read PMIC target/version (`PM660 Ver : %d.%d` printed in `0x16874`).
- **Storage Detection (`0x1c734`, `0x1d314`, `0x1d4e0`)**:
  - `FUN_0001c734` (`0x1c734`): Queries `EfiMemCardInfoProtocol` (`+0x08`) for `"UFS"` (`1`), `"EMMC"` (`0`), or `"NAND"` (`2`), falling back to `FUN_00024d28(0x100, ...)` with device-path GUIDs `0x9e834` (eMMC), `0x9e874` (UFS), `0x9e844` (NAND).
  - `FUN_0001d4e0` (`0x1d4e0`): Reads UFS/eMMC serial, vendor, FW rev, product, and manufacturing date (`UFS MD`) via `EfiMemCardInfoProtocol` for `androidboot.serialno=`.
- **Debug Banner (`FUN_00016874` @ `0x16874`)**:
  - Renders hardware/build info to screen (`FUN_00014744`) and serial log: `Build Info`, `Build Info2`, `Build Ver`, `Chip Name`, `Chip Ver`, `HW REV`, `Model Name` (`"SM-A920F"`), `PM660 Ver`, `Serial Number`, `Cable`, `DEBUG LEVEL` (`0x44494d44` `MID` / `0x47494844` `HIGH` / `0x574f4c44` `LOW`), `CARRIER`, and `DDR VERNDOR`.

### 5.2 Display (`Glib.c`), HII Font & Splash Initialization

- **Font & Text Engine (`FUN_00014b30` @ `0x14b30`, `FUN_00014744` @ `0x14744`, `FUN_0001486c` @ `0x1486c`)**:
  - `FUN_00014b30` sets `DAT_00158460 = L"sysfont2x"`, line cursor `DAT_0009fd50 = 0x7d` (`125`), and background/foreground colors via `FUN_000146d4` (`0x146d4`).
  - `FUN_0001486c` (`Glib.c`): On first call (`DAT_00158470 == 0`), opens `EfiGraphicsOutputProtocol` on `gST->ConsoleOutHandle` (`0x9ebf4`), reads `Mode->Info` (`width = +4`, `height = +8`), builds a `0x78`-byte `EFI_FONT_DISPLAY_INFO` struct with `sysfont2x` and `0x60000` (`EFI_FONT_INFO_ANY_SIZE` / style), calls `gHiiFont->StringToImage` (`*DAT_00167d98`, flags `0x82`), and blits the rendered line to screen (`(*(DAT_00158470 + 0x10))` = `GOP->Blt`, `EfiBltBufferToVideo = 2` / `3`).
- **GOP Blit Primitives (`0x17134`, `0x173ac`, `0x174ec`, `0x17a64`, `0x17dcc`)**:
  - All five functions construct `EfiGraphicsOutputProtocol` GUID on the stack (`0x9042a9de, 0x23dc, 0x4a38, ...`) and call `gBS->LocateProtocol`:
    - `0x173ac` (`DisplayBltOperationClear`): `QueryMode(0)` + `SetMode(0)` + `Blt(EfiBltVideoFill)` black (`0xff000000`, `Blue=0, Green=0, Red=0, Reserved=0xff`).
    - `0x17134` (`GlibBltOperationFillBgColor`): Maps color bitmask (`1` black, `2` `#fafafa`, `4` red, `8` green, `0x10` blue, `0x20` `#21c7c5` Download Mode teal) and fills full or top-2/3 screen.
    - `0x174ec` (`GlibDrawJpegImage`): Decodes embedded JPEG blobs (e.g. `0x9fda8`–`0xad0a7` Download Mode, `0xf0e08`–`0xfae74` warning/LPM, `0x107230`–`0x11683c` error, `0xafb48`–`0xd6188` Odin warning, `0x15066c`–`0x156214` SUD numbers `0`–`10`) into 32-bit BGRA and calls `GOP->Blt(EfiBltBufferToVideo)`.
    - `0x17a64` (`GlibDrawLine`) & `0x17dcc` (`GlibClearScreen`): Solid rectangle/screen fills.
- **Panel & Splash Handoff (`0x16ef8`, `0x241a0`, `0x260b4`)**:
  - `0x16ef8` (`GlibGetBgColorByCmdLine`) reads `L"DisplayPanelConfiguration"` (`QcomTokenSpaceGuid`), parses `lcd_id=0x...` to select background color.
  - `0x260b4` (`UpdateCmdLine`) appends `DisplayPanelConfiguration` directly to the Linux kernel command line.
  - `0x241a0` (`UpdateDeviceTree`) reads `L"DisplaySplashBufferInfo"` (`QcomTokenSpaceGuid`) and updates `/reserved-memory/splash_region` (`"Display Reserved"` `0x9D400000`, `0x02400000`) for continuous splash handoff to the Linux DRM driver.
