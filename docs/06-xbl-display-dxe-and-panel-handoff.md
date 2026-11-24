# SM-A920F (`a9y18qlte`) XBL `DisplayDxe.efi` & Panel Handoff Analysis

**Target**: Samsung Galaxy A9 (2018) `SM-A920F` (`a9y18qlte`, Qualcomm SDM660)  
**Binary**: `extracted/F_XBL/dxe/DisplayDxe.efi` (`266,240` bytes, SHA-256 `bcdf06303b40d809e8c1b459d6afd2af95148c852a75197cbbbed93b0175af54`)  
**PE32+ Layout**: AArch64 (`0xaa64`), `ImageBase = 0x0`, `EntryPoint = 0x1130` (`VA == RVA == FileOffset`), sections `.text` (`0x1000`–`0x36000`), `.data` (`0x36000`–`0x40000`), `.reloc` (`0x40000`–`0x41000`)  
**FFS / PDB Path**: FFS GUID `4138022f-06c7-4f79-9c94-7e33b511a4e7` (`FFS offset 0x27f3a0`, `0x41112` bytes); embedded PDB (`0x3f8b4`): `.../Sdm660LA_Core/RELEASE_CLANG38LINUX/AARCH64/QcomPkg/Drivers/DisplayDxe/DisplayDxe/DEBUG/DisplayDxe.dll`  
**Verification Script**: [`scripts/analyze_xbl_display.py`](../scripts/analyze_xbl_display.py)

---

## 1. `DisplayDxe.efi` Architecture, Dependencies & Initialization

### 1.1 DXE Dependency Expression (`DEPEX`)

From `extracted/F_XBL/dxe_manifest.json`, `DisplayDxe` is dispatched only after 12 protocol dependencies (`AND`-ed together) are satisfied:

| # | DEPEX Protocol GUID | Resolved Protocol / XBL DXE Owner |
|---|---|---|
| 1 | `157a5c45-21b2-43c5-ba7c-822fee5fe599` | `QcomPlatformInfoProtocol` (`PlatformInfoDxeDriver`) |
| 2 | `b0760469-970c-487a-a4b5-28db7b45cef1` | `QcomChipInfoProtocol` (`ChipInfo`) |
| 3 | `ce30ea4d-c78f-4606-9c3b-11efedcf6e87` | `QcomPmicWledProtocol` (`PmicDxe`) |
| 4 | `c1bff82d-6c92-48fb-8355-c7fb4218a4ea` | `QcomPmicIbbProtocol` (`PmicDxe`) |
| 5 | `a966cc4f-ee6c-424d-a762-8ed3b5a4a501` | `QcomPmicLabProtocol` (`PmicDxe`) |
| 6 | `4684800a-2755-4edc-b443-7f8ceb3239d3` | `QcomPmicVersionProtocol` (`PmicDxe`) |
| 7 | `b7639e28-c06b-47f0-9a13-35eeba3b51f8` | `QcomPmicLcdbProtocol` (`PmicDxe`) |
| 8 | `55e2e265-cdb2-46df-88a5-600bedef9c62` | `QcomPmicOledbProtocol` (`PmicDxe`) |
| 9 | `ad9aec18-7bf0-4809-9e96-3012309f3df7` | `QcomTlmmProtocol` (`DALTLMM`) |
| 10 | `241afae6-885f-4f6c-a7ea-c28eab79c3e5` | `QcomClockProtocol` (`ClockDxe`) |
| 11 | `b27ae8b1-3e10-4d07-ab5c-eb9a6dc6fa8f` | `QcomI2CProtocol` (`I2C`) |
| 12 | `fa5f306b-f47d-4ac4-a47d-882f8204ec30` | `QcomSpmiProtocol` (`SPMI`) |

### 1.2 Entry Point (`0x1130`) & Driver Initialization (`0x15d0`)

1. **`entry` (`0x1130`)**: Initializes stack canary (`0x1160`), calls `_ModuleEntryPoint` (`0x103c`), which executes `ProcessLibraryConstructorList` (`0x1198`: `gBS` at `0x3aba0`, `gRT` at `0x3ab88`, `HobLib`, `DxeServicesTableLib`, `UefiHiiFramework`, etc.) and invokes `DisplayDxeInitialize` (`FUN_000015d0`, `0x15d0`).
2. **Event Callbacks Registered (`0x15d0`)**:
   - `gBS->CreateEventEx(EVT_SIGNAL_EXIT_BOOT_SERVICES=0x201)` -> `FUN_00001494` (`0x1494`): Closes UI/BlockIO events and calls `FUN_00012988` (`0x12988`), which keeps splash alive if continuous splash is enabled (`"MDPLibProfile: splash enabled\n"`) or sends `DSITermSequence` + disables clocks if disabled (`"MDPLibProfile: splash disabled\n"`), then calls `FUN_0001733c` (`0x1733c`) to persist DSI PLL codes.
   - `BlockIORefresh` (`b1eb3d10-...` at `0x36020`) -> `LAB_00001530`.
   - `UI_Idle` Display On (`68c3b70d-...` at `0x21f10`) -> `FUN_00001548` (`0x1548` -> `send_display_on_cmd` `0x6d10`).
   - `UI_Idle` Display Off (`30d39942-...` at `0x21f20`) -> `FUN_00001568` (`0x1568` -> `send_display_off_cmd` `0x6dac`).
   - `UIBrightnessLow` (`8bf5eaff-...` at `0x21f30`) -> `FUN_00001588` (`0x1588` -> `FUN_00006e4c(10)`).
   - `UIBrightnessHigh` (`5bbd623c-...` at `0x21f40`) -> `FUN_000015ac` (`0x15ac` -> `FUN_00006e4c(0xff)`).
3. **MDP & Panel Initialization Flow (`0x15d0`)**:
   - `FUN_0001264c(0, 6, NULL)` -> `FUN_000166a4` (`0x166a4`): Queries `MDPPlatformConfigure(0, 10)` (supported panels), writes `L"DisplaySupportedPanelCount"` and `L"DisplaySupportedPanelList"` UEFI variables, and checks `L"DisplayPanelOverride"` (`CheckPanelOverride`).
   - `FUN_00011a0c(&info, 0)` (`0x11a0c`): Detects platform (`QcomPlatformInfoProtocol`, `QcomChipInfoProtocol`), checks `DISABLEDISPLAY` / `DISPLAYCONFIG` / `DISPLAYID`, enables core MDP clocks (`0x11df0` -> `0x114f0`: `mmss_mdss_axi_clk` = `240 MHz`, `mmss_mdss_mdp_clk` = `300 MHz`, `VDD_BIMC_SMMU`, `mmss_mnoc_*`, `mmss_bimc_smmu_*`), maps MDSS base `0x0C900000` (`0x26818`), runs `HAL_MDP_Init` (`0x0dad0`), `HAL_MDP_TrafficCtrl_Init` (`0x0f7e4`), and enables MMU SIDs (`0x159e0`).
   - `FUN_00006f34()` (`0x6f34`, `displaydriverlib_init`): Initializes Samsung panel driver state at `0x3abe8`, samples `kts1620` I2C GPIO expander (`0x193ec`), and calls `FUN_00006c48()` (`0x6c48`) to register the two Samsung panels (`S6E3FA7_AMS628RF01` and `PBA_BOOTING_FHD`).
   - `FUN_00011e30(0, &power=1)` -> `FUN_0001bbbc(0, 1, ...)` (`Panel_CDP_PowerUp`): Powers up the primary AMOLED panel (`0x196f8` + NPA `/pmic/client/disp_prim_amoled`).
   - `FUN_00011ed4(0, &mode_info)` (`0x11ed4`): Calls `FUN_00012a50` (`MDPDetectPanel`), which probes the panel via `samsung_panel_select_xml_data` (`0x6890`), parses the selected panel XML (`0x148b0`), and calls `FUN_00016b7c` (`0x16b7c`) to populate `DisplayPanelConfiguration`.
   - `FUN_000019d8(0, &mode_info)` + `FUN_0001264c(0, 4, &power)`: Registers primary display mode (`0x3aab8`) and active state (`DAT_0003ab24 = 1`).
   - Initializes GOP mode fields (`DAT_0003aa94 = 0x1000`, `PixelFormat = 1` = `PixelBlueGreenRedReserved8BitPerColor`, `0x00ff0000`/`0x0000ff00`/`0x000000ff`) and installs the UEFI protocol bundle on a new handle via `gBS->InstallMultipleProtocolInterfaces` (`0x15d0` lines 124–127).

### 1.3 UEFI Protocols Installed & Consumed

#### Protocols Installed (`0x15d0` line 124)

| GUID (`.data` RVA) | Protocol Name | Instance RVA | Vtable / Methods (RVAs) |
|---|---|---|---|
| `09576e91-6d3f-11d2-8e39-00a0c969723b` (`0x36100`) | `EfiDevicePathProtocol` | `0x36220` | Hardware Vendor Device Path (`9042a9de-...` + End Node `0x7fff0400`) |
| `9042a9de-23dc-4a38-96fb-7aded080516a` (`0x21f00` / stack) | `EfiGraphicsOutputProtocol` | `0x36238` | `+0x00 QueryMode` (`0x1c1c`), `+0x08 SetMode` (`0x1cd8`), `+0x10 Blt` (`0x1eb4`), `+0x18 Mode` (`&DAT_0003aa68`) |
| `7bfa4293-7aa4-4375-b63c-b6aab786c43c` (`0x360d0`) | `QcomDisplayPwrCtrlProtocol` | `0x36258` | `Rev=0x10000`, `+0x08 DisplayPanelPowerControl` (`0x2208`), `+0x10` (`0x25f8`), `+0x18 DisplayBackLightBrightnessLevelControl` (`0x2674`), `+0x20` (`0x270c`) |
| `f352021d-9593-4432-bf04-67b9f3b76008` (`0x360e0`) | `EfiDisplayPowerProtocol` | `0x36280` | `Rev=0x10000`, `+0x08 SetDisplayPowerState` (`0x2770`), `+0x10 GetDisplayPowerState` (`0x2aec`), `+0x18` (`0x36298`) |
| `c0dd69ac-76ba-11e6-ab24-1fc7f5575f19` (`0x360f0`) | `QcomDisplayUtilsProtocol` | `0x3a920` | `Rev=0x20000`, `+0x08 SetProperty` (`0x17230`: `0`=`UpdateDT` `0x15fa0`, `1`=`DisplayPanelOverride` `0x1726c`), `+0x10 GetProperty` (`0x172a8`), `+0x18` (`0x173f4`), `+0x20` (`0x17400`), `+0x28 SetVariable` (`0x1740c`) |

#### Protocols & Libraries Consumed

| Protocol / Service | GUID RVA | Caller Function(s) | Purpose |
|---|---|---|---|
| `QcomPlatformInfoProtocol` | `0x36140` | `0x1bbbc` | Read board/platform type (`DAT_0003f238`) |
| `QcomChipInfoProtocol` | `0x36150` | `0x1bbbc` | Read Chip ID (`DAT_0003f248`) & Chip Family (`DAT_0003f24c` = `0x43`/`0x4c`/`0x4d`) |
| `QcomPmicVersionProtocol` | `0x361e0` | `0x1bbbc` | Query PMIC revision (`+0x10`) to confirm AMOLED/PM660L configuration |
| `QcomTlmmProtocol` | `0x36190` | `0x6044`, `0x196f8`, `0x19a08`, `0x1ca14`, `0x20180` | Configure `Reset_N`, `TE`, `DISP_DET`, `disp_en` & bit-banged I2C GPIOs |
| `QcomClockProtocol` | `0x36210` | `0x114f0` | Enable/disable MDSS/MDP/DSI clocks (`0x1177c`, `0x11804`) |
| `QcomNpaProtocol` | `0x361a0` | `0x21c00`, `0x21cac` | Create NPA client `DisplayPrimAmoled` on `"/pmic/client/disp_prim_amoled"` (`0x1bbbc` line 264) |
| `QcomSpmiProtocol` | `0x1ed2c`/`0x1ed98` | `0x19c80`, `0x19cc4` | Direct SPMI register R/W for PMIC LDO6 (`3.3V`) & LDO11 (`1.8V`) |
| `QcomI2CProtocol` | `0x361b0` | `0x162bc`, `0x16420` | Hardware I2C bus init/write when XML defines I2C commands |
| `QcomPmicWledProtocol` / `Lab` / `Lcdb` / `Oledb` | `0x361c0`, `0x361d0`, `0x361f0`, `0x36200` | `0x1bbbc`, `0x1c820` | Reference CDP peripheral power rails (LCD/WLED/OLEDB/LAB) |
| `UEFI Config Lib` (`MemRegion`) | `0x2b50` -> `0x2bb4` | `0x1cd8`, `0x15bb0` | Lookup `"Display Reserved"` base/size from `uefiplat.cfg` |
| `SmemLib` (`QcomSmem`) | `0x20920`, `0x20a88` | `0x1b9dc` -> `0x1b840` | Read RAM partition table / DDR rank count from SMEM |

### 1.4 Framebuffer Allocation (`0x9D400000`, `"Display Reserved"`, 36 MiB)

In `extracted/F_XBL/cfg/uefiplat.cfg` (line 12):
```text
0x9D400000, 0x02400000, "Display Reserved", AddMem, MEM_RES, WRITE_THROUGH, LdData, WRITE_THROUGH_XN
```
When ABL (`LinuxLoader.efi` or `Odin.efi`) or BDS calls `GOP->SetMode(0)` (`FUN_00001cd8`, `0x1cd8`):
1. Calls `FUN_00002b50("Display Reserved", auStack_a0)` (`0x1cd8` line 36), obtaining physical base `0x9D400000` (`local_80`) and total size `0x02400000` (`36 MiB`).
2. Computes active framebuffer size `1080 * 2220 * 4 = 9,590,400` bytes (`0x925680`, ~`9.15 MiB`) and zeroes `0x9D400000` via `FUN_00015b4c` (`ZeroMem`).
3. Sets `GOP->Mode->FrameBufferBase = 0x9D400000` (`_DAT_0003aa80`), `FrameBufferSize = 0x925680` (`DAT_0003aa88`), `HorizontalResolution = 1080`, `VerticalResolution = 2220`, `PixelsPerScanLine = 1080`, `PixelFormat = 1` (`PixelBlueGreenRedReserved8BitPerColor`).
4. Calls `FUN_00012384(0, &pipe_cfg)` (`0x12384`): configures GPIOs (`MDPPLATFORM_CONFIG_GPIO` = `8`), sets up MDP source pipe & mixer (`0x12ea0`), calls `DsiPanelInit` (`0x12e3c` -> `0x816c`), calls `update_cmdline_ddi_id` (`0x7134`), starts the MDP pipe (`0x142ec`), and flushes `DSIInitSequence` (`0x12e84` -> `0x8240` -> `0x7c20`).
5. Calls `FUN_0001264c(0, 2, NULL)` -> `FUN_00015bb0(0)` (`0x15bb0`) to publish `UEFIDisplayInfo` and `DisplaySplashBufferInfo`.

---

## 2. Panel Detection, `lcd_id`, & Embedded Samsung AMOLED Configuration

### 2.1 Panel Registration & `kts1620` Hardware Revision Sampling

1. `displaydriverlib_init` (`0x6f34`) initializes the Samsung panel context (`0x3abe8`, `0x488` bytes) and configures the default MIPI read commands for DDI identification:
   - Register sequence in `0x6f34` lines 20–27: `0x04` (`RDDID`, Read Display Identification Information) at `0x3ac04`, plus individual 1-byte DCS read commands `0xDC` (`0x3abf8`), `0xDB` (`0x3abfa`), and `0xDA` (`0x3abfc`).
2. **`kts1620` I2C GPIO Expander (`0x193ec` -> `0x203a4` -> `0x203d8`/`0x204fc`)**:
   - Struct `kts1620_i2c` (`0x3a9b8`) defines bit-banged I2C over TLMM GPIOs `51` (`0x33`, SDA) and `52` (`0x34`, SCL) at I2C slave `0x44` (`0x203d8` line 36).
   - `0x193ec` calls `0x203a4` (registers `kts1620` channel via `0x204fc`) and reads expander pins `0x15` (`21`), `0x16` (`22`), and `0x17` (`23`) via `kts_gpio_get_value` (`0x20530`), packing a 3-bit hardware revision `pin21 | (pin22 << 1) | (pin23 << 2)` into `DAT_0003af74`.
3. **Registered Samsung Panels (`FUN_00006c48` @ `0x6c48`)**:
   - Registers `DAT_0003adcc = 2` candidate panels and sets fallback/default index `DAT_0003add4 = 1`:
     - **Index 0**: `S6E3FA7_AMS628RF01_FHD_octa_init` (`FUN_000195a8`, `0x195a8`) -> Panel ID `27` (`0x1b`), DT name `"ss_dsi_panel_S6E3FA7_AMS628RF01_FHD"`.
     - **Index 1**: `PBA_BOOTING_FHD_init` (`FUN_00019430`, `0x19430`) -> Panel ID `29` (`0x1d`), DT name `"ss_dsi_panel_PBA_BOOTING_FHD"` (uses `AMS622MR01` video-mode XML as PBA fallback when no panel responds).

### 2.2 Regulator Rails, GPIOs & Reset Sequencing (`S6E3FA7_AMS628RF01`)

| Resource | Function / Struct RVA | Configuration Details |
|---|---|---|
| **VCI (`3.3V`)** | `0x196f8` (L38–49) / `0x19a08` (L38–45) | PMIC `1` (PM660L), LDO index `5` (**LDO6**): `3,300,000 uV` (`3.3V`), `5 ms` delay after enable (`0x19cc4`, `0x19c80`). |
| **VDDR (`1.8V`)** | `0x196f8` (L50–61) / `0x19a08` (L30–37) | PMIC `0` (PM660), LDO index `10` (**LDO11**): `1,800,000 uV` (`1.8V`), `5 ms` delay after enable. |
| **Reset (`Reset_N`)** | `0x195a8` (L32–33) & `0x6044` | **TLMM GPIO `53` (`0x35`)**; reset timing tuple (`0x29a40`): `[HIGH, 10 ms] -> [LOW, 10 ms] -> [HIGH, 10 ms]`. |
| **TE (Tearing Effect)** | `0x195a8` (L18) & `0x6044` (L74–82) | **TLMM GPIO `59` (`0x3b`)** (`func=1`, input). |
| **`DISP_DET` (ESD/Detect)** | `0x196f8` (L80–96) | **TLMM GPIO `49` (`0x31`)** (`0x200e0310` -> `(0x310 >> 4) = 0x31 = 49`), configured as input. |
| **`disp_en` (`VDD3`)** | `0x195a8` (L17) vs `0x19430` (L16) | `0` (unused) on `S6E3FA7_AMS628RF01`; GPIO `49` (`0x31`) on `PBA_BOOTING`. |

### 2.3 `read_ddi_id` & `samsung_check_support_panel` (`0x6400`)

During `samsung_panel_select_xml_data` (`0x6890`), `samsung_check_support_panel` (`0x6400`) iterates through the 2 registered panels (`lVar9 = 0..1`):
1. Selects DDI read routine: `read_ddi_id` (`0x6780`, issues 3 separate DCS reads on `0xDA`, `0xDB`, `0xDC` via `FUN_000069d8` -> `0x7268` at `110 MHz` via `DSIDriver_MinimalInit` `0x7edc`) when `DAT_0003acc8[lVar9] == 0`, or `read_ddi_id_cont` (`0x669c`, 4-byte `0x04` `RDDID` read) otherwise.
2. Powers up the candidate panel (`*power_up_func`, e.g., `0x196f8`), brings DSI link into minimal LP11/read state (`DSIDriver_MinimalInit` `0x7edc` with `mdss_esc0_clk`, `mdss_pclk0_clk`, `mdss_byte0_clk` at `110 MHz`), triggers reset (`MDPPLATFORM_CONFIG_RESETPANEL` -> `0x6044(1)`), and reads `id1` (`0xDA`), `id2` (`0xDB`), `id3` (`0xDC`) into `DAT_0003abf0[0..2]`.
3. Packs the 24-bit `lcd_id = (id_DA << 16) | (id_DB << 8) | id_DC` (`0x6400` lines 78–83) and matches against the panel's bitmask and candidate list (`(target ^ read_id) & mask == 0`):
   - **For `S6E3FA7_AMS628RF01` (`0x195a8` lines 22–26)**:
     - Bitmask: `0x811040` (`DAT_0003ac08`)
     - Target IDs checked (`0..4`): `[0x810000, 0x811000, 0x811040, 0x811040, 0x811040]` (`DAT_0003ac28..0x3ac38`)
     - Any panel whose DDI ID satisfies `((lcd_id & 0x811040) == 0x810000 | 0x811000 | 0x811040)` matches (`num = 0`, Panel ID `27` / `0x1b`), closes minimal DSI (`0x75f4`), and returns `0`.
   - If the DSI read times out or fails (`DAT_0003abec == 0x10`) or neither panel matches (`lVar9 == 2`), `0x6400` falls back to `PBA_BOOTING_FHD` (`DAT_0003add4 = 1`, Panel ID `29` / `0x1d`).

### 2.4 Embedded Samsung Panel XML & DSI Sequences

`DisplayDxe.efi` embeds two Samsung XML blocks inside `.rodata` (referenced by `0x195a8` and `0x19430`) plus 9 Qualcomm/Sharp/Truly/Himax/Virtio reference XMLs (`0x2b498`–`0x33c07`) in the 25-entry Panel DT Info Table (`0x31e30`–`0x32f40`):

| Parameter | `AMS628RF01` (`0x29e8b`, `0x13fc` B) | `AMS622MR01` / `PBA_BOOTING` (`0x287a4`, `0x1206` B) |
|---|---|---|
| **DT Node / Panel ID** | `ss_dsi_panel_S6E3FA7_AMS628RF01_FHD` (`27` / `0x1b`) | `ss_dsi_panel_PBA_BOOTING_FHD` (`29` / `0x1d`) |
| **Mode & Interface** | Single DSI **Command Mode** (`InterfaceType=9`, `TrafficMode=1`) | Single DSI **Video Mode** (`InterfaceType=8`, `TrafficMode=1`) |
| **Resolution (`H × V`)** | **`1080 × 2220`** (`24 bpp`, `InterfaceColorFormat=3`, `DSIColorFormat=36`) | **`1080 × 1920`** (`24 bpp`) |
| **Horizontal Porches** | `HFP=96`, `HBP=36`, `HSYNC=24` (`total=1236`) | `HFP=92`, `HBP=36`, `HSYNC=12` (`total=1220`) |
| **Vertical Porches** | `VFP=4`, `VBP=14`, `VSYNC=2` (`total=2240`) | `VFP=7`, `VBP=7`, `VSYNC=2` (`total=1936`) |
| **Lanes / Channel / Rate** | `4` lanes, `DSIChannelId=2`, `DSIRefreshRate=0x3C0000` (`60.0 Hz`), `AutoRefresh=True` | `4` lanes, `DSIChannelId=2`, `DSIRefreshRate=0x3C0000` (`60.0 Hz`), `AutoRefresh=True` |
| **DSC / TE** | `DSIDSCEnable=False`, `DSITECheckEnable=True` (dedicated TE pin, `vSyncStartPos=2220`) | `DSIDSCEnable=False`, `DSITECheckEnable=True` (`vSyncStartPos=1920`) |
| **PHY Timings (Hex)** | `CLKZero=0x25`, `CLKPrepare=0x1F`, `CLKTrail=0x8`, `HSExit=0x25`, `HSZero=0x1F`, `HSPrepare=0x9`, `HSTrail=0xA`, `HSReq=0x6`, `CLKPre=0x35`, `CLKPost=0x0E` | `CLKZero=0x19`, `CLKPrepare=0x8`, `CLKTrail=0x8`, `HSExit=0x23`, `HSZero=0x1F`, `HSPrepare=0x7`, `HSTrail=0x9`, `HSReq=0x5`, `CLKPre=0x30`, `CLKPost=0x0D` |
| **Backlight Config** | `BacklightType=3` (DSI), `BacklightPmicControlType=0xFFF0` | `BacklightType=3` (DSI), `BacklightPmicControlType=0xFFF0` |

**`AMS628RF01` DSI Sequences (parsed & transmitted by `SendPanelXMLSequence` `0x7c20`)**:
- **`DSIInitSequence` (`0x2af1a`–`0x2b120`)**:
  - Unlock Level-2 key (`29 F0 5A 5A`) -> Sleep Out (`05 11`) -> `20 ms` delay (`FF 14`) -> TE On (`29 35 00`) -> OTP/clock/gamma/AOR/pentile/ELVSS setup (`0xCC`, `0xED`, `0xF4`, `0xC5`, `0xCA` 34-byte gamma table, `0xB1`, `0xB5`, `0xF7 03`) -> Lock key (`29 F0 A5 A5`) -> `80 ms` delay (`FF 50`) -> Trigger first frame transfer (`FE 00 00 00`, in `0x7c20` line 48 calls `0x1453c` and polls TE/BTA) -> Display On (`29 29 00`) -> `10 ms` delay (`FF 0A`).
- **`DSITermSequence` (`0x2b120`–`0x2b165`)**:
  - Display Off (`05 28 00`) -> `10 ms` delay (`FF 0A`) -> Sleep In (`05 10 00`) -> `150 ms` delay (`FF 96`).
- **Runtime Display On/Off & Brightness Control (`0x6d10`, `0x6dac`, `0x6e4c`)**:
  - `send_display_on_cmd` (`0x6d10`) / `send_display_off_cmd` (`0x6dac`): Unlock `9F 5A 5A` (`0x29`), send DCS `0x29` (Display On) or `0x28` (Display Off) (`0x15`), lock `9F A5 A5` (`0x29`).
  - `Brightness Control` (`0x6e4c`, triggered by `UIBrightnessLowEventCallBack` `0x1588` with `level=10` and `UIBrightnessHighEventCallBack` `0x15ac` with `level=0xff`): Unlock `F0 5A 5A`, write AID/brightness register `0xB1` (`B1 0B 7C` when `level <= 244`, or `B1 00 10` when `level > 244`), update `F7 03`, lock `F0 A5 A5`. (Note: `BacklightPmicControlType = 0xFFF0` disables PMIC WLED/PWM control in `0x1bbbc` case 4.)

---

## 3. `DisplayPanelConfiguration` Generation (Kernel `cmdline`)

`DisplayDxe.efi` constructs the kernel display command-line parameter string in two stages and stores it in UEFI runtime/boot-service variable `L"DisplayPanelConfiguration"` (`0x23dd0`) under `gGuid_QcomTokenSpaceGuid` (`882f8c2b-9646-435f-8de5-f208ff80c1bd` at `0x36030`):

1. **Stage 1 — `FUN_00016b7c` (`0x16b7c`, called by `MDPDetectPanel` `0x11ed4` line 204)**:
   - Searches the 25-entry DT table (`0x31e30`) for `panel_id` (`27` = `0x1b` for `S6E3FA7_AMS628RF01`).
   - Queries `MDPPlatformConfigure(0, 0xb, ...)` (`GETPANELSUPPORTFLAGS`), reading `flags = 0x1` (`single_dsi`; `bit 1` = `0` so not split-DSI).
   - Builds `DAT_0003e8e0` using literal substrings `" mdss_mdp.panel=1:"` (`0x28142`), `"dsi:0:"` (`0x2813b`), DT node `"ss_dsi_panel_S6E3FA7_AMS628RF01_FHD"`, `":1:"`, `"none"`, `":cfg:"` (`0x28194`), `"single_dsi"` (`0x28182`):
     ```text
      mdss_mdp.panel=1:dsi:0:ss_dsi_panel_S6E3FA7_AMS628RF01_FHD:1:none:cfg:single_dsi
     ```
   - Calls `FUN_0001599c(0x23dd0, 0x3e8e0, len + 1, 0)` -> `gRT->SetVariable(L"DisplayPanelConfiguration", &gGuid_QcomTokenSpaceGuid, 0x6, len + 1, buf)`.
   - Copies `DAT_0003e8e0` into `puVar5 + 0x39` (`0x3abe8 + 0xe4 = 0x3accc`).
2. **Stage 2 — `update_cmdline_ddi_id` (`FUN_00007134`, `0x7134`, called by `0x12384` lines 75–76 after `DsiPanelInit`)**:
   - Initializes stack buffer with `" lcd_id=0x"` (`0x23e04`), formats the 3 bytes of `DAT_0003abf0` in order `[2, 1, 0]` (`0x23e2c` -> `ID_DA`, `ID_DB`, `ID_DC`) using `FUN_00006970` (`%02x`), and concatenates onto `DAT_0003accc` (`0x3accc`).
   - Overwrites `L"DisplayPanelConfiguration"` via `FUN_0001599c(0x23dd0, 0x3accc, len + 1, 0)` with the complete string (e.g. for `0x811040`):
     ```text
      mdss_mdp.panel=1:dsi:0:ss_dsi_panel_S6E3FA7_AMS628RF01_FHD:1:none:cfg:single_dsi lcd_id=0x811040
     ```
3. **Consumption by `LinuxLoader.efi`**:
   - **`GlibGetBgColorByCmdLine` (`0x16ef8`)**: Reads `L"DisplayPanelConfiguration"` (`0x7b7f8`), searches for `"lcd_id=0x"`, parses the 24-bit hex ID, and inspects `(lcd_id >> 16) & 0xf` to pick the UI background color.
   - **`UpdateCmdLine` (`0x260b4` lines 343–407)**: Reads `L"DisplayPanelConfiguration"` into `DAT_0015d040` (up to `256` bytes) and appends it verbatim to the kernel command line written to `/chosen/bootargs`.

---

## 4. `DisplaySplashBufferInfo` & Continuous Splash Handoff

1. **UEFI Variables Written by `DisplayDxe.efi` (`FUN_00015bb0` @ `0x15bb0`)**:
   - Queries `"Display Reserved"` (`0x9D400000`, `MemSize = 0x02400000` = `36 MiB`).
   - Writes **`L"UEFIDisplayInfo"`** (`0x277c0`, under `EfiGraphicsOutputProtocol` GUID `9042a9de-...`, `0x78` bytes via `FUN_000158f4` `0x158f4`), containing version `0xaa0103`, platform/chip info, framebuffer base/size, width/height/stride, and DDR rank count (`0x1b840` via SMEM).
   - Populates and writes **`L"DisplaySplashBufferInfo"`** (`0x27bb0`, under `QcomTokenSpaceGuid`, attributes `0x6`, `12` bytes at `local_1c8..local_1c0`):

| Offset | Size | Field | Value on SM-A920F | Source (`0x15bb0`) |
|---|---|---|---|---|
| `+0x00` | 4 | `Version` | `1` (`0x00000001`) | `local_1c8 = 1` (L111) |
| `+0x04` | 4 | `SplashBufferAddr` | `0x9D400000` | `DAT_0003d278` (L109) |
| `+0x08` | 4 | `SplashBufferSize` | `0x02300000` (`35 MiB`) | `MemSize (0x02400000) - 0x00100000` (L110) |

2. **Top `1 MiB` Reserved for DSI PLL Codes (`0x171e8` + `0x1733c`)**:
   - `FUN_000171e8(0x9D400000, 0x02300000)` (`0x171e8`) caches `Addr` (`DAT_0003e9e4`) and `Size` (`DAT_0003e9e8`).
   - On `ExitBootServices` (`0x1494 -> 0x12988 -> 0x1733c`), `FUN_0001733c` (`0x1733c`) queries DSI PLL codes (`0x208` bytes across DSI0/DSI1 via `0x80d4`) and writes them to `0x9D400000 + 0x02300000 = 0x9F700000` (inside the excluded upper `1 MiB` of `"Display Reserved"`).
3. **FDT Patching in `LinuxLoader.efi` (`UpdateDeviceTree` @ `0x241a0` lines 354–434)**:
   - Calls `gRT->GetVariable(L"DisplaySplashBufferInfo", &gGuid_QcomTokenSpaceGuid, 0, &size, &DAT_0015d024)` (`0x7f900`).
   - Locates `/reserved-memory/splash_region` in the selected kernel FDT and validates its `reg` property length is `0x10` bytes (two 64-bit cells: `<0 Addr 0 Size>`).
   - Byte-swaps `SplashBufferAddr` (`DAT_0015d028` = `0x9D400000`) and `SplashBufferSize` (`DAT_0015d02c` = `0x02300000`) to big-endian via `fdt32_to_cpu` (`0x2f450`) and patches `<0x0 0x9d400000 0x0 0x02300000>` into `/reserved-memory/splash_region/reg` so the Linux `mdss_mdp` / `fb` driver inherits the live XBL splash framebuffer without re-initializing the panel or tearing the image.

---

## 5. Verification

Running [`scripts/analyze_xbl_display.py`](../scripts/analyze_xbl_display.py) verifies all PE32+ headers, SHA-256, 12 DEPEX GUIDs, 24 protocol/event GUIDs, 4 installed protocol vtables, `"Display Reserved"` (`0x9D400000`, `0x02400000`), all 25 DT panel entries, `AMS628RF01` & `AMS622MR01` XML tables, `kts1620` GPIOs/pins, MDSS base & clock tables, all cited `DisplayDxe.efi` / `LinuxLoader.efi` RVAs, and UEFI variable strings cleanly with exit code `0`.
