# SM-A920F (`a9y18qlte`, SDM660) `xbl.elf` — UEFI DXE Architecture, Configs, `QcomBds`, `ResetRuntimeDxe`, and `ButtonsDxe`

This report documents how `xbl.elf` (Samsung Galaxy A9 2018, `SM-A920F` / `a9y18qlte`, firmware build `A920FXXS7CVH1`, SDM660) unpacks and dispatches Qualcomm's EDK2 UEFI DXE environment, parses embedded platform configs, hands off to `abl.elf` ([LinuxLoader.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/LinuxLoader.efi) / [Odin.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/Odin.efi)), encodes/decodes reboot reasons across `gRT->ResetSystem` and PMIC PON spare registers, and maps physical keys/GPIOs/PMIC interrupts into UEFI `EFI_KEY_DATA` scan codes.

All binary claims, RVAs, GUIDs, protocol vtables, switch tables, and config values below are verified by [analyze_xbl_bds_reset_keys.py](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/scripts/analyze_xbl_bds_reset_keys.py) against the unpacked files under [extracted/F_XBL/](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL) and decompiled C under [decomp/](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/decomp). All DXE RVAs assume `ImageBase = 0x0`, `VA == RVA == FileOffset`.

---

## 1. `xbl.elf` Container, `Sec.te`, Apriori Order & Embedded Configs

### 1.1 ELF64, MBN v5, X.509 Certificate Chain & Samsung Signer Footer

Per [xbl_mbn_metadata.json](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/xbl_mbn_metadata.json), [xbl.elf](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/xbl.elf) is a `2,840,100`-byte (`0x2b5624`) `ELFCLASS64` (`EM_AARCH64`) image (`e_entry = 0x14021c90`, `16` program headers, SHA-256 `c5dcec89f2ffa937cbd488c254bccfc1056a1da9425222b6a7c8e5c630514394`):

| Container Component | Offset / VAddr | Size | Key Verified Details |
|---|---|---|---|
| ELF Header + PHT (`Seg 0`, `PT_NULL`) | File `0x0` | `0x3c0` | `e_phoff = 64`, `e_phentsize = 56`, `e_phnum = 16` |
| MBN v5 Hash Segment (`Seg 1`, `PT_NULL`) | File `0x1000`, VA `0x9fdb6000` | `0x1b28` (`memsz 0x2000`) | MBN `version = 5`, `code_size = 0x200` (16× SHA-256 hashes), `sig_size = 0x100`, `cert_chain_size = 0x1800` |
| Attestation Cert (`certs[0]`) | `Seg 1 + 0x328` | `1327` B | `CN = SecTools Test User`, `OU = 01 0000000700000000 SW_ID` (`xbl` SW_ID `0x7` / `0x0`), `OU = 02 3006000000200000 HW_ID`, `OU = 04 0020 OEM_ID`, `OU = 06 0000 MODEL_ID`, `OU = 07 0001 SHA256`, `OU = 03 0000000000000000 DEBUG` (`DEBUG = 0`, retail), `OU = 13 0001 IN_USE_SOC_HW_VERSION` |
| CA / Root Certs (`certs[1]`, `certs[2]`) | `Seg 1 + 0x857`, `+ 0xcec` | `1173` B, `1165` B | `O = Samsung Corporation, OU = DMC, CN = Samsung Root CA cert` (`m.security@samsung.com`) |
| `XBL_SEC` (`Seg 2`, `PT_LOAD`) | File `0x3000`, VA `0x14699000` | `0x131c0` | Loaded into OCIMEM/TZ region (`flags = 0x5000005`) |
| `XBL_Loader` (`Seg 3..11`, `PT_LOAD`) | File `0x161c0..0x8d5a0`, VA `0x14015000+` | — | Entry `0x14021c90`, `sbl1_config_table`, DDR/PMIC/hw_rev init |
| **UEFI FD / Outer FV (`Seg 12`, `PT_LOAD`)** | File `0x8d5a0`, VA **`0x9fc00000`** | `0x1b5800` | EFI Firmware Volume (`_FVH` magic at `Seg 12 + 0x28`), holds `Sec.te` + LZMA-compressed [inner_dxe_fv.bin](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/inner_dxe_fv.bin) |
| `XBL_Ramdump` (`Seg 13..15`, `PT_LOAD`) | File `0x242da0..0x2b5430`, VA `0x85e35000+` | — | `ramdump` segments |
| Samsung Footer (`SignerVer02`) | File `0x2b5424` | `512` B | Magic `SignerVer02`, `signer_id = 55622970R`, `build_id = A920FXXS7CVH1`, target `SM-A920F_EUR_XX_GBL0`, `SRPRI18A007`, `20220826192125` |

### 1.2 `Sec.te` (Terse Executable SEC Phase)

The first FFS file in the Outer FV (`0x9fc00000`) is [Sec.te](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/Sec.te), a `VZ` (`0x5a56`) Terse Executable image XIP-executed in place at `0x9fc00000+`:

- **TE Header (`0x28` B)**: `Machine = 0xaa64` (AArch64), `NumberOfSections = 3`, `Subsystem = 11` (`EFI_BOOT_SERVICE_DRIVER`), `StrippedSize = 0xf60`, `EntryPoint = 0x1000`, `BaseOfCode = 0x1000`, `ImageBase = 0x9fc01000` (giving XIP entry VA `0x9fc01000 + 0x1000 = 0x9fc02000`).
- **Sections**:
  - `.text`: `VAddr = 0x1000`, `VSize = 0x21000`, `RawPtr = 0x1000`, `RawSize = 0x21000`, `Characteristics = 0x60000020`
  - `.data`: `VAddr = 0x22000`, `VSize = 0x3000`, `RawPtr = 0x22000`, `RawSize = 0x3000`, `Characteristics = 0xc0000040`
  - `.reloc`: `VAddr = 0x25000`, `VSize = 0x1000`, `RawPtr = 0x25000`, `RawSize = 0x1000`, `Characteristics = 0x42000040`
- **Role**: `Sec.te` initializes CPU vectors (`0x9FF8C000`), MMU page tables (`0x9FF8D000`), UEFI stack (`0x9FF90000`), SEC heap (`0x9FF00000`), parses [uefiplat.cfg](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/uefiplat.cfg) (offset `0x1b954`) to publish the `UEFI Config Lib` HOB (`bedaeabc-5e70-4d66-9733-213d072b9d04`) and memory/register HOBs, decompresses the LZMA Outer FV section into `FV Region` (`0x9F800000`), and hands off to `DxeCore` (`"Loading DxeCore"` at file `0x1bff3` / VA `0x9fc1cff3`).

### 1.3 Apriori DXE Dispatch Sequence ([apriori_order.json](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/apriori_order.json))

The DXE apriori list specifies **82** GUIDs (`index 0..81`). Of those, **64** modules are present in [inner_dxe_fv.bin](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/inner_dxe_fv.bin) (`ui_name != null`, unpacked in [extracted/F_XBL/dxe/](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe)), while **18** GUIDs have `ui_name: null` (stripped from the retail FV: indices `32`, `48`, `50..54`, `56..57`, `63`, `71..73`, `76..77`, `79..81` — which includes absent Qualcomm debug/charger apps such as `QcomChargerApp` / `QcomChargerDxe`). Key stages in the dispatch order:

| Apriori Index | Module (`ui_name`) | GUID | Role in Boot / Handoff |
|---|---|---|---|
| `0` | `DxeCore` | `d6a2cb7f-6a18-4e2f-b43b-9920a733700a` | DXE dispatcher core (`0x9F800000`) |
| `1` | `EnvDxe` | `90a49afd-422f-08ae-9611-e788d3804845` | UEFI platform environment & `QcomEnv` |
| `9..12` | `SecurityDxe`, `ASN1X509Dxe`, `SecRSADxe`, `VerifiedBootDxe` | `5e0eae60-...`, ..., `a25f5839-...` | FV/image verification & AVB |
| `13..22` | `SmemDxe` .. `ClockDxe` | `f541d663-...` .. `4db5dea6-...` | SMEM, DAL, HWIO, ChipInfo, PlatformInfo, Glink, ULog, NPA, Clock |
| `23..29` | `DiskIoDxe` .. `FvSimpleFileSystem` | `6b38f7b4-...` .. `907125c0-...` | eMMC (`SdccDxe`), UFS (`UFSDxe`), GPT, FAT, FV filesystem |
| `34` | `ResetRuntimeDxe` | `3ae17db7-3cc5-4b89-9304-9549211057ef` | `gRT->ResetSystem` + `QcomResetReasonProtocol` |
| `41` | `QcomBds` | `5a50aa81-c3ae-4608-a0e3-41a2e69baf94` | `EfiBdsArchProtocol` (`BdsEntry` at `0x1ce8`) |
| `42..47` | `DALTLMM`, `I2C`, `SPMI`, `SPI`, `PmicDxe`, `AdcDxe` | `8681cc5a-...` .. `5a5cb8ca-...` | Bus drivers & PMIC/SPMI protocols (`PmicPwrOn`, `PmicPon`, `PmicGpio`) |
| `49, 55` | `UsbfnDwc3Dxe`, `UsbConfigDxe` | `94f8a6a7-...`, `cd823a4d-...` | USB peripheral controller (used by `Odin.efi` / Fastboot) |
| `58..61` | `SimpleTextInOutSerial`, `ConPlatformDxe`, `ConSplitterDxe`, `GraphicsConsoleDxe` | `857a8741-...` .. `cccb0c28-...` | Console splitter (`ConIn`/`ConOut`/`ErrOut`) |
| `62` | `ButtonsDxe` | `5bd181db-0487-4f1a-ae73-820e165611b3` | Physical keypad polling -> `EfiSimpleTextInputExProtocol` |
| `64..70` | `TsensDxe`, `Muic`, `Chg`, `DisplayDxe`, `TzDxe`, `LimitsDxe`, `MdtpDxe` | `f09ad92e-...` .. `409d636e-...` | Samsung `Muic`/`Chg`, Display splash/panel, TZ SCM, MDTP |
| `74..78` | `HashDxe`, `RngDxe`, `MpPowerDxe` | `3adf8dda-...` .. `88abf42e-...` | Crypto & multi-core power |

### 1.4 Embedded Configuration Files ([extracted/F_XBL/cfg/](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg))

1. **[uefiplat.cfg](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/uefiplat.cfg)** (`Version = 3`, `MaxMemoryRegions = 64`):
   - `[MemoryMap]` (**14 regions**):
     - `0x80000000` (`0x05800000`): `"Kernel"` (`Reserv`, `WRITE_BACK_XN`)
     - `0x86000000` (`0x00200000`): `"SMEM"` (`Reserv`, `UNCACHED_UNBUFFERED_XN`)
     - `0x94000000` (`0x09400000`): `"DXE Heap"` (`Conv`, `WRITE_BACK_XN`)
     - `0x9D400000` (`0x02400000`): `"Display Reserved"` (`LdData`, `WRITE_THROUGH_XN`)
     - `0x9F800000` (`0x00200000`): `"FV Region"` (`BsData`)
     - `0x9FA00000` (`0x00200000`): `"ABOOT FV"` (`Reserv` — ABL container load target)
     - `0x9FC00000` (`0x00300000`): `"UEFI FD"` (`BsData` — `xbl.elf` `Seg 12` XIP FV)
     - `0x9FF00000` (`0x0008C000`): `"SEC Heap"`, `0x9FF8C000` (`0x1000`): `"CPU Vectors"`, `0x9FF8D000` (`0x3000`): `"MMU PageTables"`, `0x9FF90000` (`0x40000`): `"UEFI Stack"`, `0x9FFD0000` (`0x27000`): `"DBI Dump"`, `0x9FFF7000` (`0x8000`): `"Log Buffer"`, `0x9FFFF000` (`0x1000`): `"Info Blk"`
   - `[RegisterMap]` (**33 MMIO regions**): includes `IMEM Base` (`0x14680000`), `IMEM Cookie Base` (`0x146BF000`), `BOOT_CONFIG` (`0x00070000`), `GCC CLK CTL` (`0x00100000`), `SECURITY CONTROL` (`0x00780000`), `MPM2_SLP_CNTR` (`0x010A3000`), `MPM2_PSHOLD` (`0x010AC000`), `TCSR_TCSR_REGS` (`0x01FC0000`), `TLMM CSR` (`0x03100000`), `PMIC ARB SPMI` (`0x08000000`), `USB30_PRIM` (`0x0A800000`), `PERIPH_SS` (`0x0C000000`), `QTIMER` (`0x17900000`), `APCS_GIC500_*` (`0x17A00000`/`0x17B00000`).
   - `[ConfigParameters]` (`ConfigParameterCount = 50`, `PlatConfigFileName = "uefiplatLA.cfg"`, `OsTypeString = "LA"`):
     - `EnableShell = 0x1` *(present in config, ignored by retail `QcomBds.efi`)*
     - `SharedIMEMBaseAddr = 0x146BF000`, `GCCResetValueAddress = 0x146BF028`
     - `DloadCookieAddr = 0x01FD3000`, `DloadCookieValue = 0x10`
     - `MemoryCaptureModeOffset = 0x1C`, `AbnormalResetOccurredOffset = 0x24`, `DBIDumpDDRBase = 0x9FFD0000`
     - `PwrBtnShutdownFlag = 0x0`, `PSHoldOffset = 0xC000`, `PSHoldSHFT = 0x0`
     - `SecurityFlag = 0xC4` (`CommonMbnLoadFlag 0x4 | LoadSecAppFlag 0x40 | LoadKeymasterFlag 0x80`; `SecBootEnableFlag 0x1` and `VariableServicesFlag 0x10` are `0` here)
     - `TzAppsRegnAddr = 0x86D00000`, `TzAppsRegnSize = 0x02200000`
     - `DefaultChargerApp = "QcomChargerApp"`, `DefaultBDSBootApp = "LinuxLoader"`, `EnableLogFsSyncInRetail = 0x0`

2. **[BDS_Menu.cfg](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/BDS_Menu.cfg)**:
   Defines Qualcomm's engineering `[BDS Menu]` (`Indent = 1`, `FirstRow = 1`):
   - `Exit`, `SecurityToggleApp` (`/SecureBootEnable`, `/SecureBootDisable`), `DebugPolicyToggleApp` (`/DebugPolicyEnable`, `/DebugPolicyDisable`, `/ConfigPpiDisplay`), `RPMBProvision` (`-Prompt`), `Shell` (`-nomap -nostartup`), `Cmd` (`"BootUSBFirst"`, `"Reboot"`, `"edl"`), `UsbfnMsdApp` (`"MassStorage"`), nested `Menu` submenus (`Usb_Menu.cfg`, `Pmic_Menu.cfg`, `Uefi_Menu.cfg`), and `Fastboot` (`App = Fastboot`, `FvGuid = "046fae99-cf2e-49ed-a6a8-a1488b7e80d3"` — the `ABOOT FV` GUID). *Note: none of these menu items or `.cfg` submenus are parsed by retail `QcomBds.efi`.*

3. **[SecParti.cfg](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/SecParti.cfg)** (`Version = 0x0100`):
   Maps TZ secure variable/storage partitions for `SecurityDxe` / TZ:
   - `[RPMB.128KB]` (`DevId = 3`): `qcom.tz.uefisecapp` `AppPartitionId = 3` (`RT_S_NV`, `160` sectors), `AppPartitionId = 4` (`RT_NS_NV`, `48` sectors); `qcom.tz.winsecapp` `AppPartitionId = 5` (`fTPM`, `40` sectors).
   - `[RPMB.256KB]` (`DevId = 3`): same IDs with `184`, `208`, and `80` sectors respectively.
   - `[GPT]` (`DevId = 8`, `PartitionGuid = "8BF4B4F0 BAAE CF4E 9142 5DC30CDC3E77"`): `AppPartitionId = 1` (`BS_S_NV`, `65536` bytes), `AppPartitionId = 2` (`BS_NS_NV`, `131072` bytes).

4. **[QcomChargerCfg.cfg](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/QcomChargerCfg.cfg)** (`CfgVersion = 25`):
   Qualcomm reference `QcomChargerConfig_VbattTh_Sdm660.cfg`:
   - `[PlatformCommon]`: `ChargingTermCurrent = 200` mA, `BatteryIdTolerance = 8%`, `DebugBoardBatteryIdMin/Max = 2000..14000` Ω, `RegularBatteryIdMin/Max = 15000..137000` Ω, `SmartBatteryIdMin/Max = 240000..450000` Ω, `UnknownBatteryBehavior = 3` (Regular charging), `DebugBoardBehavior = 2` (Boot to HLOS), `BootToHLOSThresholdInMv = 3600`, `EmergencyShutdownVbatt = 3200`, `DispSignOfLifeMaxThresholdMv = 3700`, `SocBasedBoot = FALSE`, `LoadBatteryProfile = FALSE`, `EnableChargerWdog = 1`, `DeviceSkinHotInC = 70`/`80`, `ChargerHotInC = 80`/`90`, `TsensHighTemp = 85`/`Extreme = 90`/`Low = 75`, `FgCondRestart = TRUE`, `VBattEstDiffThreshold = 30` mV, `ChargerLedConfig = 1`.
   - `[PlatformMTP]`: `ChgFvMax = 4350` mV, `ChgFccMax = 2000` mA, JEITA limits `-20 / 0 / 10 / 45 / 60 / 70` °C, `VBtEmpty = 2850` mV.
   - `[PlatformQRD]`: `ChgFvMax = 4400` mV, `ChgFccMax = 3000` mA, JEITA limits `-20 / 0 / 10 / 45 / 55 / 60` °C, `VBtEmpty = 2850` mV.

5. **[BATTERY.PROVISION](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/BATTERY.PROVISION)**:
   Three `PMI8998GUI - 2.0.0.54` fuel-gauge SRAM profile blocks (`Profile_Revision = 24`, SRAM addresses `018..04F`, byte offsets `0..3`):
   - `Ascent_with_connector_3450mAh_averaged_MasterSlave_Jan6th2017`: `Batt_id = 60000` Ω, `Float_Voltage = 4350` mV, `Nom_Batt_capacity = 3450` mAh, `Therm_B = 3435`, `Checksum = 96AC`.
   - `QRD8997_ST1031GA_3000mAh_averaged_MasterSlave_Jan10th2017`: `Batt_id = 68000` Ω, `Float_Voltage = 4400` mV, `Nom_Batt_capacity = 3000` mAh, `Therm_B = 3380`, `Checksum = D299`.
   - `Itech_B00826LF_3000mAh_ver1660_averaged_MasterSlave_Jan10th2017`: `Batt_id = 100000` Ω, `Float_Voltage = 4350` mV, `Nom_Batt_capacity = 3000` mAh, `Therm_B = 3435`, `Checksum = FB8F`.

6. **[tracer_event.cfg](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/cfg/tracer_event.cfg)** (`[SW Event Information]`):
   Nine QDSS SW trace events: `QDSS_INITIALIZED` (`1`), `TRACER_EVENT_TEST` (`0`), `TRACER_EVENT_TEST2` (`0`), `CLOCK_EVENT_INIT` (`1`), `CLOCK_EVENT_CLOCK_STATUS` (`1`), `CLOCK_EVENT_CLOCK_FREQ` (`1`), `CLOCK_EVENT_SOURCE_STATUS` (`1`), `CLOCK_EVENT_SOURCE_FREQ` (`1`), `CLOCK_EVENT_SOURCE_CONFIG` (`1`).

---

## 2. `QcomBds.efi` Boot & ABL Handoff

[QcomBds.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe/QcomBds.efi) (`277` decompiled functions in [decomp/XBL_QcomBds/](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/decomp/XBL_QcomBds)) implements `gEfiBdsArchProtocolGuid` (`665e3ff6-46cc-11d4-9a38-0090273fc14d` at `0x111a0`).

### 2.1 Initialization & `BdsEntry` (`0x1ce8`)

1. **Entry (`0x1130` -> `0x103c` -> `0x203c`)**: Runs EDK2 library constructors (`0x1198`), sets the `FwVerStr` UEFI variable under `QcomTokenSpaceGuid` (`882f8c2b-9646-435f-8de5-f208ff80c1bd` at `0x11060`) via `0x1fb8`, and installs `gEfiBdsArchProtocolGuid` pointing to struct `0x113a0` whose `+0x00` entry pointer is `BdsEntry` (`0x1ce8`).
2. **`BdsEntry` (`0x1ce8`)**:
   - Calls `FUN_00001c58()`: reads `"DefaultBDSBootApp"` via `FUN_000025cc` (`UEFI Config Lib` HOB `bedaeabc-...` at `0x11050`), then calls `FUN_00001b98()` which invokes `FUN_0000c84c()`.
   - **Retail DebugFV Gate (`0xc84c`)**: `0xc84c` consists solely of `mov x0, #-0x7ffffffffffffffd; ret` (`0x8000000000000003` = `EFI_UNSUPPORTED`). This hardcodes retail gating in `0x1b98`: the `QcomScmProtocol` (`77ed108d-...` at `0x11230`) call `0x2000113` and `DebugFvLoader.c` (`FUN_00003a64`, `"LoadDebugFv"`) are **never reached**.
   - Updates `gST->FirmwareVendor = L"Qualcomm Technologies, Inc."` and recalculates `gST->Hdr.CRC32`.
   - Calls `PlatformBdsInit` (`FUN_0000bee8(&vol_down_flag)`).
   - If `PlatformBdsInit` returns (only on ABL failure/exit): checks variable `AttemptUSBFirst` (`77fa9abd-0359-4d32-bd60-28f4e78f784b` at `0x11030`) or `vol_down_flag == 1`, then boots `BootNext` (`0x20c4`), `BootOrder` (`0x21f8` -> `0x1768`), or falls back to `0x1aec(2, 1, 1)`.

### 2.2 `PlatformBdsInit` (`0xbee8`) & Unconditional `"LinuxLoader"` Dispatch

1. **`PublishImemVars` (`0xb96c`)**: Opens `HWIODxeDriver` (`9e61de7c-...` at `0x11380`), writes `Shared_IMEM_Base` (`0x146BF000` from `"SharedIMEMBaseAddr"`), maps `"+MPM2_SLP_CNTR"` (`MPM2_SLP_CNTR_ADDR`), and inspects `BOOT_CONFIG` (`*(uint32*)0x00786070 & 0x3e == 8` via `0xc86c`) to select `"+UFS"` vs `"+PERIPH_SS_SDC1_SDCC_SDCC5_HC"` (`BootDeviceBaseAddr`) under `QcomTokenSpaceGuid`.
2. **Console & Platform Info (`0x8a78`, `0x3050`)**: Connects `ConIn`, `ConOut`, `ErrOut`, publishes `PlatformInfo` via `QcomChipInfoProtocol` + `QcomPlatformInfoProtocol`, and prints `Core 0 Freq` via `ClockDxe` (`241afae6-...` at `0x11360`).
3. **LogFS Sync (`0xb5b0`, `0x2f74(L"logfs")`)**: Mounts/flushes `logfs` only when `EnableLogFsSyncInRetail == 1`; because `uefiplat.cfg` sets `EnableLogFsSyncInRetail = 0x0`, `0xb6fc` skips LogFS sync (`"BDS: LogFs sync skipped, %r\r\n"`). `0xb5b0` also flushes NV vars (`0x11270`), capsule partition (`0x11330` / `SdccDxe` `0x11350`), and notifies `QcomScmProtocol+0x30`.
4. **ABL Launch (`0xbee8` -> `0xc8b4`)**:
   - Reads config `"DefaultBDSBootApp"` -> `"LinuxLoader"`.
   - Prints `UEFI Total : %d ms` (`0xb51c`).
   - **Unconditionally** calls `LaunchAppFromGuidedFv` (`FUN_0000c8b4(&DAT_00011160, "LinuxLoader", NULL)`), where `0x11160` is **`046fae99-cf2e-49ed-a6a8-a1488b7e80d3`** (`"ABOOT FV"` mapped at `0x9FA00000`, `2 MiB`, containing `abl.elf`'s [LinuxLoader.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/LinuxLoader.efi) and [Odin.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/Odin.efi)).

### 2.3 Retail Gating of `BDS_Menu.cfg`, `EnableShell`, and `QcomChargerApp`

- **No BDS Menu / Shell**: Although `uefiplat.cfg` still sets `EnableShell = 0x1` and `BDS_Menu.cfg` is packed inside `inner_dxe_fv.bin`, the retail `QcomBds.efi` binary contains **no references** to `"BDS_Menu.cfg"`, `"EnableShell"`, or `"QcomChargerApp"` (verified in both ASCII and UTF-16LE). Hotkey scanning (`FUN_000033f0(local_100, 3)` checking `ScanCode == 2` / `Vol-`) is only reached inside `0xbee8` *after* `0xc8b4` returns, alongside `"Press any key to shutdown"` (`0xb884`) and `SetupMode`/`SecureBoot` (`0xbc18`) — i.e., error fallback if `ABOOT FV` fails to load or exits.
- **No `QcomChargerApp` Launch**: `uefiplat.cfg` lists `DefaultChargerApp = "QcomChargerApp"`, but neither `QcomChargerApp` nor `QcomChargerDxe` exists in `apriori_order.json` / `inner_dxe_fv.bin`, and `QcomBds.efi` never branches on battery/charging state. Instead, `QcomBds.efi` always launches `LinuxLoader.efi`, which implements Samsung off-mode charging (`LPMModeChecker` at `0x13464`) itself using `Chg`/`Muic` DXE protocols.

---

## 3. `ResetRuntimeDxe.efi` (`QcomResetReasonProtocol` + `gRT->ResetSystem`)

[ResetRuntimeDxe.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe/ResetRuntimeDxe.efi) (`180` decompiled functions in [decomp/XBL_ResetRuntimeDxe/](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/decomp/XBL_ResetRuntimeDxe)) installs both `gEfiResetArchProtocolGuid` (`27cfac88-46cc-11d4-9a38-0090273fc14d` at `0x90b0`) and `QcomResetReasonProtocol` (`a022155a-4828-4535-a499-11f15240b91b` at `0x90c0`).

### 3.1 Protocol Layout, Initialization & PMIC/SPMI Hardware Path

- **Init (`0x1628` -> `0x31f0`)**:
  - Reads `DloadCookieAddr` (`0x01FD3000`), `PSHoldOffset` (`0xC000`), and `PSHoldSHFT` (`0x0`) from `UEFI Config Lib`.
  - Maps `"MPM2_MPM"` via `HWIODxeDriver` (`9e61de7c-...` at `0x9110`) to `0x010AC000` (`MPM2_PSHOLD`, stored at `[0x92a0]`).
  - Initializes runtime SPMI (`0x6e18`, `SPMIRuntime.c`) and QTimer (`0x6fec`, `0x17922000`, `TimetickRunTime.c`), registers `ExitBootServices` / `SetVirtualAddressMap` callbacks, sets `gRT->ResetSystem = FUN_000015bc`, and installs `QcomResetReasonProtocol`.
- **`QcomResetReasonProtocol` Struct (`0x9130`)**:
  - `+0x00`: `Revision = 0x10002`
  - `+0x08`: `GetResetReason` wrapper `0x1704` (`mov x0, x1; mov x1, x2; mov x2, x3; b 0x3074` — strips `This` and tail-calls `0x3074`)
  - `+0x10`: `ClearResetReason` wrapper `0x1714` (`b 0x31b4`)
  - `+0x18`: `0x10000`
- **PMIC PON Spare Register (`XVDD_RB_SPARE` = `0x88f`)**:
  - `GetResetReason` (`0x3074`) locates `PmicPonProtocol` (`9ba45b66-efa4-441c-a3e4-ed2224786be2` at `0x9120`), calls `+0x20` (`GetSpareReg(0, 3, &val)`), and shifts `val >> 1` (7 bits `[7:1]`). It returns string `L"UNKNOWN"` (`0x7a1a`) when the 7-bit code is `0`, or `L"RESET_PARAM"` (`0x7a02`) when non-zero.
  - `ClearResetReason` (`0x31b4`) calls `FUN_0000349c(0)`.
  - `FUN_0000349c(code)` locates `9ba45b66-...` and calls `+0x28` (`SetSpareReg(0, 3, code << 1, 0xfe)`).
  - Verified in [PmicDxe.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe/PmicDxe.efi) vtable `0x2f638` (`Revision = 0x10009`): `+0x20` (`0x3174` -> `0xfe0c`) and `+0x28` (`0x31a4` -> `0xfe74`) compute `add w1, w20/w21, #0x88c`. For `SpareReg = 3` (`XVDD_RB_SPARE`), the physical PMIC SPMI register is **`0x88c + 3 = 0x88f`** (`PM_PON_XVDD_RB_SPARE`, bits `[7:1]`).

### 3.2 `gRT->ResetSystem` (`0x15bc` -> `0x2f60`) Dispatch: `RESET_PARAM`, `EDL`, and PMIC Reset

1. **Display Blank (`0x1538`)**: Locates `DisplayDxe` power protocol (`7bfa4293-...` at `0x90d0`) and powers off the panel.
2. **Cookie Handling (`0x2f60`)** *(when not at HLOS runtime)*:
   - If `DataSize != 0 && ResetData != NULL` and `ResetData` starts with UTF-16LE `L"RESET_PARAM"` (`0x7a02`), reads the 1-byte reset code at `((uint8_t*)ResetData) + StrSize(L"RESET_PARAM")` (`+0x18`) and writes it to `XVDD_RB_SPARE` (`0x88f`) via `FUN_0000349c(code)`. Otherwise writes `0` (`FUN_0000349c(0)`).
3. **EDL (`EfiResetPlatformSpecific`, `ResetType == 3` -> `0x2f14`)**:
   - Compares `ResetData` against `L"EDL"` (`0x79fa`). On match, calls `0x5558()` and `0x55d4()`, which read `"DloadCookieAddr"` (`0x01FD3000`, `TCSR_BOOT_MISC_DETECT`) and execute TZ SCM call `0x2000502` (`0x69c4`) writing `(DloadCookieAddr, 0)` then `(DloadCookieAddr, 1)` to set the EDL dload cookie, then configures warm/hard reset `0x563c(0)`.
4. **PMIC PON + `PS_HOLD` Sequence (`0x563c` -> `0x56a8` / `0x5900`)**:
   - Uses config tables at `0x8b18..0x8bc4` to program PMIC PON reset control registers (`0x85a` `PON_PS_HOLD_RESET_CTL`, `0x85b` `PON_PS_HOLD_RESET_CTL2`, `0x88d`, `0x8c4`, `0x80a`, `0x804`, `0x800`) over runtime SPMI (`0x5f84`/`0x5fe8`/`0x6054`), then deasserts `MPM2_PSHOLD` (`0x010AC000` -> `0` at `0x3058`).

### 3.3 Reset Reason Strings & Hex Codes (`0x00`..`0x49`) Consumed by `LinuxLoader.efi` (`0x12b9c`)

Notice a key architectural boundary: **`ResetRuntimeDxe.efi` does not store a table of Linux `reboot <reason>` ASCII names** (`"recovery"`, `"bootloader"`, etc.); instead, `ResetRuntimeDxe` only parses `L"RESET_PARAM"` + 1-byte code (for UEFI callers like `LinuxLoader`/`Odin`) and `L"EDL"`, while the Linux HLOS `sec_reboot` driver translates `reboot <arg>` strings into 7-bit codes written directly to `PM_PON_XVDD_RB_SPARE` (`0x88f` `[7:1]`). On the next boot, `LinuxLoader.efi` at `0x12b9c` calls `QcomResetReasonProtocol->GetResetReason` (`+0x08` -> `0x3074`) and branches on the returned 7-bit value via the 74-entry jump table at **`0x7a188`** (`0x00..0x49`):

| Code | UEFI / HLOS Producer (`ResetData` / `sec_reboot` / PON) | `LinuxLoader.efi` `0x12b9c` Action | Return / Effect |
|---|---|---|---|
| `0x00` | Normal boot / `L"UNKNOWN"` (`XVDD_RB_SPARE == 0`) | `0x12cfc`: `mov w19, wzr` | Returns `0` (`BootNormal`) |
| `0x01` | `reboot download` / `RESET_PARAM + 0x01` | `0x12d04`: `mov w19, #2` | Returns `2` -> launches `Odin.efi` (Download Mode) |
| `0x02` | `reboot recovery` / `RESET_PARAM + 0x02` | `0x12d0c`: writes `0x100` to `param +0x08` (`0x19684`) | Returns `1` -> launches Recovery |
| `0x03` | `reboot` variant / `RESET_PARAM + 0x03` | `0x12d14`: `mov w19, #5` | Returns `5` |
| `0x14` | Clear `param` boot mode (`RESET_PARAM + 0x14`) | `0x12d1c`: if caller mode `2` or `4`, clears `param` block 0 (`0x186f8(0)`) | Returns `0` (`BootNormal`) |
| `0x15` | `reboot recovery` / FOTA (`0x10000`) | `0x12d3c`: writes `0x10000` to `param +0x08` (`0x19684`) | Returns `1` -> launches Recovery |
| `0x1a` | Samsung reboot mode `0x1a` | `0x12d44`: `mov w19, #6` | Returns `6` |
| `0x20..0x2a` | `sales_code` / carrier / recovery sub-reasons `1..11` | `0x12cd8`: writes `(code & 0xf) + 1` (`1..11`) to `param +0x08` (`0x19684`) | Returns `1` -> launches Recovery |
| `0x2c` | Samsung reboot mode `0x2c` | `0x12d4c`: `mov w19, #8` | Returns `8` |
| `0x30` | `debug 0x4f4c` (`"DLOW"`, Debug Level LOW) | `0x12d54`: `0x18d58(0x4f4c)` (`"DLOW"`) + `0x18b28(0)` (ForceUpload OFF) | Updates `param`, `BootNormal` (`0`) |
| `0x31` | `debug 0x494d` (`"DMID"`, Debug Level MID) | `0x12d60`: `0x18d58(0x494d)` (`"DMID"`) + `0x18b28(5)` (ForceUpload ON) | Updates `param`, `BootNormal` (`0`) |
| `0x32` | `debug 0x4948` (`"DHIG"`, Debug Level HIGH) | `0x12d70`: `0x18d58(0x4948)` (`"DHIG"`) | Updates `param`, `BootNormal` (`0`) |
| `0x33` | `cpdebug` ON (`0x5500`) | `0x12d7c`: `0x19020(0x5500)` (`param +0x14 = 0x5500`) | Updates `param`, `BootNormal` (`0`) |
| `0x34` | `cpdebug` OFF (`0x55ff` -> `0`) | `0x12d84`: `0x19020(0x55ff)` (`param +0x14 = 0`) | Updates `param`, `BootNormal` (`0`) |
| `0x35` | `"PC"` mode (`0x4350`) | `0x12d94`: `0x19570(0x4350)` (`param +0x1c8 = 0x4350`) | Updates `param`, `BootNormal` (`0`) |
| `0x36`, `0x3f` | Clear `"PC"`/`"BM"` flag (`0`) | `0x12cf4`: `0x19570(0)` (`param +0x1c8 = 0`) | Updates `param`, `BootNormal` (`0`) |
| `0x3e` | `"BM"` mode (`0x4d42`) | `0x12d9c`: `0x19570(0x4d42)` (`param +0x1c8 = 0x4d42`) | Updates `param`, `BootNormal` (`0`) |
| `0x48` | Force Upload ON | `0x12dac`: prints `"Force Upload : ON\n"`, calls `0x18b28(5)` | ForceUpload = `5`, `BootNormal` (`0`) |
| `0x49` | Force Upload OFF | `0x12dc4`: prints `"Force Upload : OFF\n"`, calls `0x18b28(0)` | ForceUpload = `0`, `BootNormal` (`0`) |
| Other `0x04..0x47` | Unmapped codes (default jump table target) | `0x12ddc` | Returns `0` (`BootNormal`, unchanged) |
| `L"EDL"` (`ResetType=3`) | `reboot edl` / `ResetRuntimeDxe` `0x2f14` | Sets `0x01FD3000 = 1` via SCM `0x2000502` | Enters PBL EDL (9008) before XBL/ABL |

*(Separately, `xbl_loader.elf` logs low-level PON/GCC reset strings `SP`, `WP`, `DP`, `KP`, `MP`, `PP`, `RP`, `BP`, `NP`, `TP` near `0x1407aea4`, and `GCCResetValueAddress` `0x146BF028` records GCC reset status in Shared IMEM.)*

---

## 4. `ButtonsDxe.efi` (`EfiSimpleTextInputExProtocol`) & Key Mapping

[ButtonsDxe.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe/ButtonsDxe.efi) (`114` decompiled functions in [decomp/XBL_ButtonsDxe/](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/decomp/XBL_ButtonsDxe)) polls hardware keys via PMIC protocols and exposes UEFI keystrokes through `ConSplitterDxe`.

### 4.1 Installed Protocols & Physical Key/PMIC/GPIO Matrix

- **Entry (`0x1dd0`)**: Calls `ButtonsInit` (`0x3d28`), installs `EfiSimpleTextInProtocol` (`0x7130`: `{0x1438, 0x1450, 0x0}`), `EfiSimpleTextInputExProtocol` (`0x7148`: `{0x1524, 0x153c, 0x0, 0x168c, 0x1694, 0x1838}`), and `EfiDevicePathProtocol` (`0x7178`), creates a periodic timer event (`0x1c4c`, `0x100` TPL), and checks `QcomPmicPwrOnProtocol+0x18` (`97044b58-...` at `0x7090`) for `(pon_reason & 0x81) == 0x80` (`PowerKeyPressed`).
- **Keymap Initialization (`0x3b6c`)**: Queries `PlatformInfoDxe` (`0x70e0`), stores platform keymap ID `0x1e` (`30`) at `0x7414`, and copies **5** `uint32` KeyIDs from `0x71b8`: **`{1, 2, 3, 9, 0}`** (`num_keys = 5`).
- **GPIO Configuration (`0x3cac`)**: Calls `PmicGpioProtocol+0x08` (`EnableInput` via `0x3c40`, which subtracts 1 from the 1-based GPIO argument) for `(pmic=1, arg=7)` -> **PMIC 1 GPIO 6 (`VOL+`)** and `(pmic=1, arg=8)` -> **PMIC 1 GPIO 7 (`BIXBY`)**. (SoC TLMM GPIOs are not used for these keys; all 4 physical buttons live on PMIC0 PON / PMIC1 GPIO.)

| Physical Button | `PollButtonArray` (`0x3f78`) Slot | Hardware Source (`PmicDxe`) | Active Polarity | KeyID (`0x71b8`) | `ScanCode` Bit (`0x39ac`) |
|---|---|---|---|---|---|
| **Power** | `buf[0]` (`0x4070`) | `PmicPonProtocol` (`9ba45b66-...` `+0x18` -> `0xfa88`) PON `KPDPWR` RT IRQ (`0x808`/`0x8c0`) | Active high | `1` | **`0x80`** |
| **Volume Up (`VOL+`)** | `buf[1]` (`0x3ef0(1, 7)`) | `PmicGpioProtocol` PMIC `1` GPIO `6` (`arg=7`) | Active low (`!= 1`) | `2` | **`0x01`** |
| **Volume Down (`VOL-`)** | `buf[2]` (`0x3e84(1)`) | `PmicPonProtocol` PON `RESIN` RT IRQ (`idx 1`) | Active high | `3` | **`0x02`** |
| **Bixby** | `buf[3]` (`0x3ef0(1, 8)`) | `PmicGpioProtocol` PMIC `1` GPIO `7` (`arg=8`) | Active low (`!= 1`) | `9` | **`0x20`** |
| *(Unused)* | — | — | — | `7` | **`0x40`** *(never generated; `num_keys = 5`, `0x71b8` has no `7`)* |

### 4.2 Polling, Bitmask Encoding & ABL Key Combination Matrix

- **`ConvertEfiKeyCode` (`0x39ac`)**: Whenever the button-pressed mask is non-zero and edge state `[0x7410]` permits, ORs the active `ScanCode` bits (`0x01 | 0x02 | 0x40 | 0x80 | 0x20`) into `EFI_KEY_DATA.Key.ScanCode` (`uint16`, leaving `UnicodeChar = 0`) and pushes the 4-byte `EFI_INPUT_KEY` into the driver's ring buffer (`0x2d20`).
- **Consumed in [LinuxLoader.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/LinuxLoader.efi) (`0x26c20` -> `0x12e10`)**:
  `FUN_00026c20` polls `ConIn->ReadKeyStroke` / `ReadKeyStrokeEx`, returning `ScanCode`:

  | `ScanCode` (`w8`) | Physical Key Combo | `0x12e10` Branch Target | Resulting Boot / UI Action |
  |---|---|---|---|
  | `0x21` | `Bixby + Vol+` (`0x20 \| 0x01`) | `0x12f38` -> `0x130d0` | **Enter Recovery Mode** (`1`) |
  | `0xa1` | `Power + Bixby + Vol+` (`0x80 \| 0x20 \| 0x01`) | `0x12f54` -> `0x130d0` | **Enter Recovery Mode** (`1`) |
  | `0x02` | `Vol-` | `0x12f30` -> `0x12f64` | **Download Mode Warning Prompt** (Odin confirmation) |
  | `0x22` | `Bixby + Vol-` (`0x20 \| 0x02`) | `0x12f40` -> `0x12f64` | **Download Mode Warning Prompt** |
  | `0x82` | `Power + Vol-` (`0x80 \| 0x02`) | `0x12f5c` -> `0x12f64` | **Download Mode Warning Prompt** |
  | `0xa2` | `Power + Bixby + Vol-` (`0x80 \| 0x20 \| 0x02`) | `0x12f4c` -> `0x12f64` | **Download Mode Warning Prompt** |
  | *(Pivot `0x81`)* | `Power + Vol+` (`0x80 \| 0x01`) | `0x12f28`: `cmp w8, #0x81; b.gt` | *Binary-search pivot only; loops back to `0x12eb8` (not accepted)* |
  | `0x01` (at prompt) | `Vol+` | `0x12ff8` -> `0x130d8` | **Confirm Download Mode -> launch `Odin.efi`** (`2`) |
  | `0x02` (at prompt) | `Vol-` | `0x13000` -> `0x13008` | **Cancel Download Mode -> normal reboot (`0x14638`)** |

- **Consumed in [Odin.efi](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/Odin.efi) (`0x1fb7c`)**:
  - `0x01f4c` / `0x01f7c` / `0x0f77c` / `0x0fe7c` / `0x0ff24` call `FUN_0001fb7c` (key reader).
  - `0x0fed4` (`0x0ff34: cmp w8, #0x80`) checks **Power (`0x80`)** inside the Odin UI screen handler.
  - `0x0fff4` (`0x10028: cmp w9, #1`, `0x10030: cmp w9, #2`) checks **`Vol+` (`0x01`)** and **`Vol-` (`0x02`)** for confirmation/navigation prompts inside Odin.
