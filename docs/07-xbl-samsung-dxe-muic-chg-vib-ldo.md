# SM-A920F (`a9y18qlte`, SDM660) Custom XBL Samsung DXE Drivers (`Muic.efi`, `Chg.efi`, `Vib.efi`, `NpaLdo.efi`)

**Target Firmware**: Samsung Galaxy A9 2018 (`SM-A920F`, `a9y18qlte`, SDM660) — `A920FXXS7CVH1`  
**ImageBase Convention**: All four XBL DXE modules are PE32+ AArch64 (`0xaa64`, Subsystem `11` = `EFI_BOOT_SERVICE_DRIVER`) binaries with `ImageBase = 0x0` and `EntryPoint = 0x1130`, where `VA == RVA == FileOffset` in `extracted/F_XBL/dxe/` and `decomp/XBL_{Muic,Chg,Vib,NpaLdo}/`.  
**Verification Script**: [`scripts/analyze_xbl_samsung_dxe.py`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/scripts/analyze_xbl_samsung_dxe.py)

---

## 1. Overview & Shared Architectural Patterns

Samsung extends Qualcomm's SDM660 XBL UEFI DXE environment with four board-specific drivers loaded from the XBL Firmware Volume (`apriori_order.json` indices `65`–`66` for `Muic`/`Chg`, plus `Vib` and `NpaLdo` in `extracted/xbl_dxe_modules.json`):

| DXE Module | File Size | SHA-256 (prefix) | Installed Protocol | Protocol GUID | `.text` / `.data` / `.reloc` | Hardware Controlled |
| --- | --- | --- | --- | --- | --- | --- |
| [`Muic.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe/Muic.efi) | `40,960` B | `abc694a2f3ba49a3...` | `SamsungMuicProtocol` | `2cc73155-a1f9-4c4b-88e2-caf9390e126a` | `0x1000+0x7000` / `0x8000+0x1000` / `0x9000+0x1000` | SM5705 MUIC (`0x25`), S2MM005 CCIC (`0x33`), KTS1620 (`0x22`) |
| [`Chg.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe/Chg.efi) | `49,152` B | `57924ff1bb0dd406...` | `SamsungChargerProtocol` | `3c7596fa-0058-4496-a648-6d14be4023b2` | `0x1000+0x9000` / `0xa000+0x1000` / `0xb000+0x1000` | SM5705 Charger (`0x49`), SM5705 FG (`0x71`), `BATT_THERM` ADC |
| [`Vib.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe/Vib.efi) | `32,768` B | `2f00f0413952e399...` | `SamsungVibratorProtocol` | `aa2e776d-8c9c-4268-998a-8b0a13bf0501` | `0x1000+0x5000` / `0x6000+0x1000` / `0x7000+0x1000` | S2DOS03 (`0x60`) LDO4 (`3.3 V`) Coin DC Motor |
| [`NpaLdo.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F_XBL/dxe/NpaLdo.efi) | `28,672` B | `04a9c965e07bb22e...` | `SamsungNpaLdoProtocol` | `6c3dbb2c-4354-4f5a-9e2f-40658db24402` | `0x1000+0x4000` / `0x5000+0x1000` / `0x6000+0x1000` | PMIC NPA resource `/pmic/client/api_test` |

### 1.1 Common EDK2 Startup & Bit-Banged `GpioI2CLib`

1. **EDK2 Scaffolding (`0x1130` → `0x103c` → `0x1198`/`0x117c`)**:
   - `_ModuleEntryPoint` (`0x1130`) initializes stack canary (`0x1160`) and invokes `0x103c` (`DriverEntryPoint.c`), which runs `ProcessLibraryConstructorList` (`UefiBootServicesTableLib`, `ArmArchTimerLib`, `UefiRuntimeServicesTableLib`, `HobLib`, `HiiFramework`/`DebugMask` `4c8a2451-...`) and then tail-calls the module's DXE init function (`Muic@0x145c`, `Chg@0x15e4`, `Vib@0x1400`, `NpaLdo@0x13e4`) via `gBS->InstallMultipleProtocolInterfaces` (`gBS + 0x148`).
2. **GPIO Bit-Banged I2C (`GpioI2CLib.c` in `Muic`, `Chg`, `Vib`)**:
   - Rather than using Qualcomm's hardware QUP `I2C.efi` DXE, `Muic.efi`, `Chg.efi`, and `Vib.efi` all link `GpioI2CLib.c`, which locates `QcomTlmmProtocol` (`ad9aec18-7bf0-4809-9e96-3012309f3df7`) and drives SDM660 TLMM GPIOs directly (`+0x08` `ConfigGpio`, `+0x18` `GpioIn`, `+0x20` `GpioOut`).
   - Each I2C bus is registered via a `0x24`-byte (`36`-byte) descriptor (`gpio_i2c_register`, max `14` channels):
     - `+0x00` (`16` B): ASCII bus name (`SM5705_gpio`, `S2MM005_gpio`, `kts1620_i2c`, `sm5705_chg_i2c`, `sm5705_fg_i2c`, `s2dos03_i2c`)
     - `+0x10` (`u32`): **SCL GPIO** number
     - `+0x14` (`u32`): **SDA GPIO** number
     - `+0x18` (`4` B) / `+0x1c` (`4` B): TLMM pin config bytes (`func`, `dir` at `+0x19`/`+0x1f`, `pull` at `+0x1a`/`+0x20`, `drive` at `+0x1b`/`+0x21`).
   - **Important 8-bit vs 7-bit Slave Addressing**: `gpio_i2c_write` / `gpio_i2c_read` transmit bits `7..1` of the `slave` argument MSB-first and append `0` (Write) or `1` (Read) for bit 0. Thus all slave constants passed inside the binaries are **8-bit shifted addresses** (`addr_7bit << 1`).

### 1.2 Summary of All GPIO Bit-Banged I2C Buses & Slaves

| DXE Driver | Config Name (RVA) | SCL GPIO | SDA GPIO | 8-bit Addr (R/W) | 7-bit Addr | Target IC |
| --- | --- | --- | --- | --- | --- | --- |
| `Muic.efi` | `SM5705_gpio` (`0x6cf8`) | `73` (`0x49`) | `72` (`0x48`) | `0x4a` | **`0x25`** | Silicon Mitus SM5705 MUIC |
| `Muic.efi` | `S2MM005_gpio` (`0x79f8`) | `21` (`0x15`) | `20` (`0x14`) | `0x66` (W) / `0x67` (R) | **`0x33`** | Samsung S2MM005 USB-PD / CCIC |
| `Muic.efi` | `kts1620_i2c` (`0x8150`) | `51` (`0x33`) | `52` (`0x34`) | `0x44` | **`0x22`** | Kinetic KTS1620 24-bit I2C GPIO Expander |
| `Chg.efi` | `sm5705_chg_i2c` (`0x8508`) | `73` (`0x49`) | `72` (`0x48`) | `0x92` (W) / `0x93` (R) | **`0x49`** | Silicon Mitus SM5705 Charger |
| `Chg.efi` | `sm5705_fg_i2c` (`0x91c0`) | `56` (`0x38`) | `55` (`0x37`) | `0xe2` (W) / `0xe3` (R) | **`0x71`** | Silicon Mitus SM5705 Fuel Gauge |
| `Vib.efi` | `s2dos03_i2c` (`0x56c0`) | `70` (`0x46`) | `66` (`0x42`) | `0xc0` | **`0x60`** | Samsung S2DOS03 Companion PMIC (LDO4) |

---

## 2. `Muic.efi` — `SamsungMuicProtocol` (`2cc73155-a1f9-4c4b-88e2-caf9390e126a`)

### 2.1 Initialization (`0x145c` → `0x2500` → `0x2574`) & Ops Table

`MuicDxeEntry` (`0x145c`) calls `0x2500` (`"MUIC Device : SM5705\n"`), sets the internal ops pointer (`DAT_00008260 = 0x80f0`), invokes `sm5705_muic_init` (`0x2574`), and installs `SamsungMuicProtocol` from `.data` at `0x80b0`.

**`SamsungMuicProtocol` Vtable (`0x80b0`, `0x28` bytes)**:

| Offset | Value / RVA | Method Name | Underlying Implementation | ABL `LinuxLoader.efi` Callers |
| --- | --- | --- | --- | --- |
| `+0x00` | `0x0000000000000001` | `Revision` (`1`) | — | — |
| `+0x08` | `0x13c0` | `GetDeviceType(UINT32 *DevType)` | `0x2554` → `SM5705_ops[6]` (`0x2848`) | `0x156cc` (`MuicGetDeviceType`), `0x15984` (`MuicGetJigType`: returns `(*t - 6) < 4`, i.e., `1` for `{6,7,8,9}`) |
| `+0x10` | `0x13ec` | `SetPath(UINT32 Path)` | `0x2564` → `SM5705_ops[2]` (`0x26e4`) | `0x157a8` (`MuicSetPath`), called with `1` (`AP USB`) on Download/Odin launch (`0x1794`) |
| `+0x18` | `0x1404` | `GetVbusStatus(UINT32 *Vbus)` | `0x2534` → `SM5705_ops[5]` (`0x280c`) | Consumed by `Chg.efi` (`0x2bb8` via `SamsungMuicProtocol+0x18`) |
| `+0x20` | `0x1430` | `GetAdcMode(UINT32 *Mode)` | `0x2544` → `SM5705_ops[7]` (`0x2b2c`) | Consumed by `Chg.efi` (`0x2bb8` via `SamsungMuicProtocol+0x20`) |

**Internal `SM5705_ops` (`0x80f0`) & `S2MM005` CCIC / `KTS1620` Tables**:
- `SM5705_ops @ 0x80f0`: `[0]=0`, `[1]=0x2574` (`init`), `[2]=0x26e4` (`set_path`), `[5]=0x280c` (`get_vbus`), `[6]=0x2848` (`get_attached_device`), `[7]=0x2b2c` (`get_adc_mode`), `[9]=0x1f` (`ADC_OPEN`).
- `ccic_ops @ 0x8210`: `[0]=0x5260` (`init_ccic_ic` → `S2MM005_gpio` `0x59e4` + `S2MM005_read_adc` `0x5288`), `[1]=0x5288` (`S2MM005_read_adc`), `[2]=0x536c` (`s2mm005_read_pd_state`, consumed by `Chg.efi` via `CcicProtocol`? Wait—note `Chg.efi` locates `bfab1be9-...` if a separate CCIC DXE is present, while `Muic.efi` embeds `S2MM005` directly).
- `kts1620_ops @ 0x8178`: `[0]=0x4ba8` (`kts1620_gpio_init`: pulses GPIO `0x21`=`33` via `0x4f90` for `100 us`×2, then writes direction registers `0x0c..0x0e` and output registers `0x04..0x06` from table `0x81a8`), `[1]=0x4ccc` (`skip`), `[2]=0x4d00` (`get`), `[3]=0x4d84` (`set`), `[4]=0x4e40` (`dir_in`), `[5]=0x4ee4` (`dir_out`).

### 2.2 `sm5705_muic_init` (`0x2574`) & `SetPath` (`0x26e4`) Register Writes

1. **Initialization (`0x2574`)**:
   - Initializes `S2MM005` (`0x51d8`), registers `SM5705_gpio` (`0x2bc8`, SCL=`73`, SDA=`72`), and initializes `KTS1620` (`0x4b54`/`0x4ba8`..`0x4b78`, resetting `USB_ID_CTR`).
   - Reads `SM5705` `CTRL` reg `0x02` (`slave 0x4a` / 7-bit `0x25`):
     - If `CTRL == 0x1a` (manual switching already active): clears bit 0 of reg `0x30` (`reg30 &= ~1`) and bit 2 of reg `0x14` (`reg14 &= ~4`).
     - Otherwise writes `CTRL` (`0x02`) = `0x1e` (`INT_MASK | WAIT | MANUAL_SW | RAW_DATA`).
   - Writes reg `0x16` = `0x26` (`AFC_CTRL` / MUIC timing), runs `0x2848` (`get_attached_device`), and logs `CTRL` (`0x02`) and `DEV_ID` (`0x01`).
2. **`SetPath(path)` (`0x26e4`, jump table `0x6a38`)**:
   - Writes `MANSW1` (reg `0x13`) according to `path`:
     - `path == 1` (`USB` / AP USB): `0x24` (`0010_0100b` — DM/DP connected to AP USB)
     - `path == 2` (`UART` / AP UART): `0x6c` (`0110_1100b` — DM/DP connected to AP UART)
     - `path == 3` (`CP USB` / Audio?): `0x90` (`1001_0000b`)
     - `path == 4` (`CP UART` / Open?): `0xb4` (`1011_0100b`)
   - Then writes `CTRL` (reg `0x02`) = `0x1a` (clears bit 2 `AUTO_SW` to force manual switch path `MANSW1`) and reads back `0x02` and `0x13` for debug output (`"[MUIC] ctrl = 0x%x\n"`, `"[MUIC] mansw1 = 0x%x\n"`).

### 2.3 Complete ADC / RID JIG & Cable Detection Table (`0x2848` & `0x5288`)

`get_attached_device` (`0x2848`) reads `SM5705` interrupt/status registers `0x03`, `0x04`, `0x05`, and ADC register `0x09`:
- **Direct SM5705 ADC Path** (when `reg 0x09 != 0x16` and `reg 0x09 != 0x1f`, jump table `0x6a90`): directly maps `0x18..0x1d`.
- **CCIC (`S2MM005`) + VBUS + DEVT1/DEVT3 Path** (when `reg 0x09` is `0x16` [RID controlled by CCIC] or `0x1f` [`ADC_OPEN`]):
  1. Calls `S2MM005_read_adc` (`0x5288`): writes `0xaa` to `S2MM005` reg `0x10`, waits `20 us`, reads 1 byte from reg `0x50` (`RID`), defaulting to `7` (`RID_OPEN`) if `0`.
  2. Reads `SM5705` `VBUS_STATUS` (`reg 0x15 & 1` via `0x280c`), `reg 0x17`, `DEVT1` (`0x0a`), `DEVT2` (`0x0b`), and `DEVT3` (`0x0c`).
  3. Dispatches via jump table `0x6a58` (`S2MM005` RID `1..7`), and for `RID_OPEN` (`7`) with `VBUS == 1`, inspects `DEVT1` (`0x0a`) then `DEVT3` (`0x0c`):

| `SM5705` `ADC` (`0x09`) | `S2MM005` `RID` (`0x50`) | `SM5705` `VBUS` (`0x15&1`) / `DEVT1` (`0x0a`) / `DEVT3` (`0x0c`) | Returned `DevType` | Meaning / Side Effects | ABL & `Chg.efi` Behavior |
| --- | --- | --- | --- | --- | --- |
| `0x16` / `0x1f` | `1` (`RID_0`) | — | **`11`** (`0xb`) | USB OTG (`0 Ω`) | `Chg` `0x2bb8`: `1` if VBUS!=0 else `0` |
| `0x16` / `0x1f` | `2` (`RID_1K`) | — | **`10`** (`0xa`) | `1 kΩ` MHL/accessory | `Chg` sets `700 mA` |
| `0x18` | `3` (`RID_255K`) | — | **`7`** (`0x7`) | `255 kΩ` JIG USB ON | `MuicGetJigType=1`; `Chg` `100 mA` |
| `0x19` | `4` (`RID_301K`) | — | **`6`** (`0x6`) | `301 kΩ` JIG USB OFF (**Download JIG**) | `MuicGetJigType=1`; ABL `0x12e10` cold-boot → **Odin** (`1`) |
| `0x1c` | `5` (`RID_523K`) | — | **`9`** (`0x9`) | `523 kΩ` JIG UART OFF (**UART JIG**); calls **`SetPath(2)`** (`UART`) | `MuicGetJigType=1`; ABL `0x23d78` DT `cpufreq-boot-limit` |
| `0x1d` | `6` (`RID_619K`) | — | **`8`** (`0x8`) | `619 kΩ` JIG UART ON (**UART JIG**); calls **`SetPath(2)`** (`UART`) | `MuicGetJigType=1`; ABL `0x23d78` DT `cpufreq-boot-limit` |
| `0x16` / `0x1f` | `7` (`RID_OPEN`) | `VBUS == 0` | **`0`** (`0x0`) | Detached / `NONE` | No cable |
| `0x16` / `0x1f` | `7` (`RID_OPEN`) | `VBUS == 1`, `DEVT1 ∈ {0x04, 0x08}` | **`1`** (`0x1`) | **USB** (SDP / Dedicated USB) | `500 mA` input/charge; VolDown+Cable → Odin |
| `0x16` / `0x1f` | `7` (`RID_OPEN`) | `VBUS == 1`, `DEVT1 == 0x20` | **`2`** (`0x2`) | **CDP** (Charging Downstream Port) | `500 mA` (`Chg` default `450 mA` / `500 mA` input) |
| `0x16` / `0x1f` | `7` (`RID_OPEN`) | `VBUS == 1`, `DEVT1 == 0x40` | **`3`** (`0x3`) | **TA / DCP** (Travel Adapter) | `1500 mA` input, `2100 mA` fast-chg |
| `0x16` / `0x1f` | `7` (`RID_OPEN`) | `VBUS == 1`, `DEVT1` other, `DEVT3 == 0x04` | **`1`** (`0x1`) | **USB** (`devt3`) | `500 mA` |
| `0x16` / `0x1f` | `7` (`RID_OPEN`) | `VBUS == 1`, `DEVT3 ∈ {0x02,0x20,0x40,0x80}` | **`3`** (`0x3`) | **TA / DCP** (`devt3`) | `1500 mA` input, `2100 mA` fast-chg |
| `0x16` / `0x1f` | `7` (`RID_OPEN`) | `VBUS == 1`, fallback | **`1`** (`0x1`) | Default cable type **USB** | `500 mA` |

*(Note: `0x1a`, `0x1b` in direct ADC mode return `0`; `0x2b2c` `GetAdcMode` returns `0` if not ADC-oriented, `1` if SM5705 ADC `!= 0x1f`, or `2` if `S2MM005` CCIC reports a non-`0`/non-`7` RID.)*

---

## 3. `Chg.efi` — `SamsungChargerProtocol` (`3c7596fa-0058-4496-a648-6d14be4023b2`)

### 3.1 Consumed Protocols & Initialization (`0x15e4` → `0x2a18`)

`ChgDxeEntry` (`0x15e4`) calls `charging_func_init` (`0x2a18`), which:
1. Sets internal function tables `DAT_0000a2c8 = 0xa188` (`sm5705_charger_ops`) and `DAT_0000a2d0 = 0xa208` (`sm5705_fg_ops`).
2. Locates:
   - `SamsungMuicProtocol` (`0xa0b0`: `2cc73155-...`) → `DAT_0000a2f0`
   - `AdcProtocol` (`0xa0c0`: `61740cc4-916f-4471-b0dc-00c6f43a7fc6`, provided by `AdcDxe.efi`) → `DAT_0000a2f8`
   - `CcicProtocol` (`0xa0d0`: `bfab1be9-653f-4624-ae2d-7b7f00cc91f3`) → `DAT_0000a300` (optional; logs error if absent)
   - `QcomTlmmProtocol` (`0xa090`: `ad9aec18-...`, inside `GpioI2CLib.c` `0x6c1c`) → `DAT_0000a330`
3. Initializes `sm5705_chg_i2c` (`0x328c`, SCL=`73`, SDA=`72`) and `sm5705_fg_i2c` (`0x3e80`, SCL=`56`, SDA=`55`), reads `SM5705` FG device ID (`0x4584`, FG reg `0x00`), and calls `chg_get_charger_status` (`0x2bb8`); if `cable_type == 13` (USB-PD) sets input current to `DAT_0000a2e8`, or if `cable_type == 3` (TA) sets `1500 mA`.

### 3.2 Complete `SamsungChargerProtocol` Vtable (`0xa0e0`, `0x90` bytes)

*(Note: Immediately following `+0x88` at `0xa170` is the `EfiHiiFrameworkGuid` / `DebugMask` struct `[0x10000, 0x2394, 0x23b8]`.)*

| Offset | Wrapper RVA | Method Signature | Implementation Chain | ABL `LinuxLoader.efi` Caller(s) |
| --- | --- | --- | --- | --- |
| `+0x00` | `0x1` (val) | `UINT64 Revision` | — | — |
| `+0x08` | `0x13c0` | `SetChgCurrent(UINT32 mA, UINT32 Type)` | `0x27bc` → `0x357c` (`sm5705_chg_set_charging_current`) | *(internal / unused by ABL)* |
| `+0x10` | `0x13d8` | `SetChgCurrentByType(UINT32 Type)` | `0x2808` → `0x35c4` (`sm5705_set_charging_current_by_type`) | `0x15aac` ← `0x13464`, `0x138d4` |
| `+0x18` | `0x13f0` | `SetMaxCurrent(UINT32 mA, UINT32 Type)` | `0x2770` → `0x3534` (`sm5705_chg_set_input_limit`) | `0x15b88` ← `0x1794` (`(500, 1)`), `0x13464`, `0x138d4` |
| `+0x20` | `0x1408` | `SetEnCharge(UINT32 BuckEn, UINT32 ChgEn)` | `0x26f0` → `0x3420` (`sm5705_set_charger_state`) | `0x15c6c` ← `0x1794` (`(1, 0)`), `0x13464`, `0x138d4` |
| `+0x28` | `0x1420` | `SetChgReconfig(VOID)` | `0x284c` → `0x3620` (WPCIN `400`, VBUSIN `500`, I_chg `500`, enable `(1,1)`) | `0x15d50` ← `0x13464` (cable-less boot shutdown) |
| `+0x30` | `0x1438` | `CheckBattery(VOID)` | `0x273c` → `0x34f0` (`state(0,0)` → `100 ms` → `state(1,1)`) | *(internal)* |
| `+0x38` | `0x1450` | `GetChargerStatus(UINT32 *CableType)` | `0x2bb8` (`chg_get_charger_status`) | `0x15e1c` ← `0x13464`, `0x138d4`, `0x13b48` |
| `+0x40` | `0x147c` | `SetWatchdogTimer(UINT32 Val)` | `0x2880` → `0x3664` (no-op `ret`) | *(stub)* |
| `+0x48` | `0x1494` | `SetWatchdogKick(VOID)` | `0x28c4` → `0x3668` (no-op `ret`) | *(stub)* |
| `+0x50` | `0x14ac` | `GetFactoryMode(UINT8 *FactoryMode)` | `0x28f8` → `0x36c4` (reads `DAT_0000a318`) | *(unused by ABL)* |
| `+0x58` | `0x14d8` | `ChargerInit(VOID)` | `0x3080` (`dev_charging_init`) | `0x158b8` ← `0x1794` (early boot) |
| `+0x60` | `0x14f0` | `FgGetVoltage(UINT32 *VcellMv)` | `0x29e8` → `0x4468` (`sm5705_fuel_gauge_read_vcell`) | `0x15f2c` ← `0x12a9c`, `0x13464`, `0x138d4`, `0x13b48` |
| `+0x68` | `0x151c` | `FgGetSoc(UINT32 *SocX10)` | `0x29d8` → `0x440c` (`sm5705_fuel_gauge_read_soc`) | `0x1603c` ← `0x12a9c`, `0x138d4` |
| `+0x70` | `0x1548` | `FgGetFgReset(UINT32 *FgReset)` | `0x2a08` → `0x45e0` (reads `DAT_0000a2e0`) | `0x1614c` ← `0x706bc` (`" fg_reset=%d"` cmdline) |
| `+0x78` | `0x1574` | `GetBattTemp(INT32 *TempX10)` | `0x2d90` (`get_battery_temperature`) | `0x1625c` ← `0x13464` (rejects `>= 85.1°C` / `0x353`) |
| `+0x80` | `0x15a0` | `FgCheckModelData(UINT32 *NeedInit)` | `0x29f8` → `0x45c8` → `0x45ec` | `0x16360` ← `0x13464` |
| `+0x88` | `0x15cc` | `FuelgaugeInit(VOID)` | `0x29a4` → `0x3ee4` (`sm5705_init_fuelgauge`) | `0x16488` ← `0x13464` (if `FgCheckModelData != 0`) |

### 3.3 SM5705 Charger (`0x49`) Registers, Current Tables & `ChargerInit` (`0x3080`)

- **SM5705 Charger Register Map (`slave 0x92`/`0x93`, 7-bit `0x49`)**:
  - `0x08` (`STATUS1`): bit `4` (`0x10`) = wireless charger detect (`0x36d0`).
  - `0x0c` (`CNTL`): bits `[2:0]` = operation mode; `sm5705_set_buck_enable(en)` (`0x38c8`) sets `0x05` (buck/CHG mode) when `en != 0` else `0x00`, and waits `10 ms`.
  - `0x0d` (`VBUSCNTL`, bits `[6:0]`): VBUS input current limit `I_limit = 100 + val * 25 mA` (`0x3e3c`, clamped `[100, 3275] mA` / `0xccb`).
  - `0x0e` (`WPCINCNTL`, bits `[6:0]`): Wireless input limit `I_limit = 100 + val * 25 mA` (`0x3ad0`, ramped in `±100 mA` steps with `1 s` delay).
  - `0x0f` (`CHGCNTL1`, bits `[2:0]`): set to `3` (`AICL` threshold) in `sm5705_init_charger` (`0x3300`).
  - `0x10` (`CHGCNTL2`, bits `[5:0]`): VBUS fast-charge current `I_chg = 100 + val * 50 mA` (`0x3df0` → `0x3a60`, clamped `[100, 3250] mA` / `0xcb2`).
  - `0x11` (`CHGCNTL3`, bits `[5:0]`): WPC fast-charge current `I_chg = 100 + val * 50 mA` (`0x39fc`).
  - `0x12` (`CHGCNTL4`, bits `[5:0]`): `BATREG` float voltage (`0x346c`, default `4350 mV` = `0x10fe` → `((4350 - 4010) / 10) + 2` = `0x24`, clamped `[3800..4629] mV`).
  - `0x13` (`CHGCNTL5`, bits `[3:0]`): set to `0x0a` (`TOPOFF` / `DONE`) in `0x3300`.
  - `0x14` (`CHGCNTL6`): set to `0x08` in `0x3300`.
  - `0x15` (`CHGCNTL7`, bit `1`): cleared (`0`) in `0x3300` and `0x3d94`.
  - **Charger Enable GPIO (`0x3964`)**: Configures TLMM **GPIO `63` (`0x3f`)** (`gpio_tlmm_config(0x3f, 0, OUT, NO_PULL, 2mA)` + `gpio_set(0x3f)`).
- **Per-Cable Input & Fast-Charge Current Table (`0x35c4` jump table `0x8438`, `0x3c84` jump table `0x84a0`)**:

| Cable Type | Source | `SetChgCurrentByType` (`0x35c4`) | `sm5705_set_auto_current` (`0x3c84`) Input Limit | `sm5705_set_auto_current` Fast-Chg |
| --- | --- | --- | --- | --- |
| `0` (`NONE`) | Detached | `450 mA` | `500 mA` | `0 mA` (buck on, chg off) |
| `1` (`USB`) | SDP / OTG+VBUS | `500 mA` | `500 mA` | `500 mA` (`450 mA` if `vcell < 3100 mV`) |
| `2` (`CDP`) | CDP | `450 mA` | `500 mA` | `0 mA` |
| `3` (`TA`) | DCP / TA | `2100 mA` (`0x834`) | `1500 mA` (`0x5dc`) | `2100 mA` (`0x834`) |
| `4` (`QC / HVDCP`) | High-voltage TA | `2100 mA` (`0x834`) | `1800 mA` (`0x708`) | `2100 mA` (`0x834`) |
| `5` (`WC / WPC`) | Wireless (`0x36d0`) | `1050 mA` (`0x41a`) | `900 mA` (`0x384`, WPCIN) | `1050 mA` (`0x41a`, WPC_FAST) |
| `6..9` (`JIG_*`) | `301K/255K/619K/523K` | `100 mA` | `500 mA` | `100 mA` |
| `10` (`1K`) | `RID_1K` | `700 mA` | `700 mA` | `700 mA` |
| `11..12` | Misc | `450 mA` | `500 mA` | `0 mA` |
| `13` (`0xd`) | USB-PD (`CcicProtocol`) | `DAT_0000a2e8` (`501..1500 mA`) | `DAT_0000a2e8` | `DAT_0000a2e8` |

- **`ChargerInit` / `dev_charging_init` (`0x3080`) Flow**:
  1. Reads `cable_type` (`0x2bb8`), `jig_type` (`0x3010`), initial `vcell` (`0x4468`), and `temp` (`0x2d90`).
  2. If `temp >= 851` (`85.1°C`, `0x353`), prints over-temperature warning and calls `set_charger_state(1, 0)` (charging disabled).
  3. Otherwise calls `sm5705_init_charger` (`0x3300`). If `cable_type != 0 && jig == 0`, loops up to `16`×`1 s` while `vcell < 3100 mV` (`0xc1c`, or `< 2800 mV` `0xaef` capped at 16s with `450 mA` pre-charge): once `vcell >= 3400 mV` (`0xd48`), sets charging state `(DAT_0000a2e4 == 0, 0)` and `SetChgCurrentByType(cable_type)`.
  4. Calls `fuel_gauge_init` (`0x3ee4`), then enables charging `(1, 1)` if `temp < 85.1°C && cable_type != 0 && DAT_0000a2e4 == 0`.

### 3.4 SM5705 Fuel Gauge (`0x71`), `FgGetVoltage`, `FgGetSoc`, `FgGetFgReset` & `FuelgaugeInit`

All FG registers are **16-bit words** (`WriteFGRegisterWord` `0x4644`, `ReadFGRegisterWord` `0x46f8`, `slave 0xe2`/`0xe3`, 7-bit `0x71`):
- **`FgGetVoltage` (`0x4468`)**: Checks `FgCheckModelData` (`0x45ec`), unlocks `PARAM` (`0x13 = 0x370f`) if uninitialized, reads `0x06` (`OCV`) then `0x07` (`VCELL`, retrying up to 3× if `0xffff`), and converts fixed-point `Q5.11` Volts to mV:
  $$\text{Vcell (mV)} = \left((\text{raw} \gg 11) \& 7\right) \cdot 1000 + \left((\text{raw} \& \text{0x7ff}) \cdot 1000 \gg 11\right)$$
- **`FgGetSoc` (`0x440c`)**: Reads FG reg `0x05` (`SOC`) and converts `Q8.8` percent to tenths of a percent (`0..1000`):
  $$\text{SOC (0.1\%)} = \left((\text{raw} \gg 8) \& \text{0xff}\right) \cdot 10 + \left((\text{raw} \& \text{0xff}) \cdot 10 \gg 8\right)$$
- **`FgCheckModelData` (`0x45c8` → `0x45ec`)**: Reads FG reg `0x10` (`OP_STATUS`); if bit `4` (`0x10`) is set, model is already loaded (`returns 0`, no init needed); if clear, `returns 1` (init needed).
- **`FuelgaugeInit` (`0x3ee4`) & `FgGetFgReset` (`0x45e0`)**:
  1. Reads `0x1f` (`FG_VER` / `CTRL_FLAG`) and `jig_type` (`0x3010`).
  2. If `(reg_0x1f & 0xf1) == 0x10` and `jig == 0`, keeps `DAT_0000a2e0 = 0` (`fg_reset=0`); otherwise waits `100 ms`, performs `sm5705_fuel_gauge_sw_reset` (`0x4874`: writes `0x00a6` to reg `0x91`, waits `300 ms`), and checks `0x45ec()`.
  3. When `0x45ec()` returns `1` (needs init):
     - Writes `0x1f |= (jig != 0) | 0x10`, `0x91 = 0xa000`, `0x13 = 0x370f` (`PARAM` unlock).
     - Writes `RCE0..2` (`0x20..0x22`) = `[0x04e1, 0x03e6, 0x01d7]` (`0x918a`), `DTCD` (`0x23`) = `0x0001`, `RS` (`0x24`) = `0x0051`, `VIT_PERIOD` (`0x1a`) = `0x3506`.
     - Loads 2×16-word battery OCV/SOC lookup tables from `0x914a` into FG regs `0xa0..0xaf` (`0x1400..0x2400`) and `0xb0..0xbf` (`0x0000..0x1b5a`) with `10 ms` per write.
     - Configures `RS_MIX_FACTOR` (`0x25`=`0x146`), `RS_MAX` (`0x26`=`0x3800`), `RS_MIN` (`0x27`=`0x7a`), `MIX_RATE` (`0x1b`=`0x403`), `MIX_INIT_BLANK` (`0x1c`=`4`), `0x50`=`0x8000`, `0x51`=`0`, `0x52`=`0x7c`, `0x53`=`0x7c`, `0x90`=`0x60`, `0x12`=`3`, `CNTL` (`0x01`=`0xc400`), `0x13`=`0xf` (`PARAM` lock), runs `sm5705_calculate_iocv` (`0x48bc`), writes `0x2e` = calculated `iOCV`, and sets **`DAT_0000a2e0 = 1`** (`fg_reset=1`).
  4. `FgGetFgReset` (`0x1548` → `0x45e0`) returns `DAT_0000a2e0`, which ABL `UpdateCmdLine` (`LinuxLoader.efi @ 0x706bc`, `0x1614c`) formats onto the Linux kernel command line as **`fg_reset=%d`**!
  5. Also clears `PARAM_RUN_UPDATE` (`0x14`) to `0` if non-zero.

### 3.5 `GetBattTemp` (`0x2d90`) & `BATT_THERM` ADC Table (`0x8380`)

`GetBattTemp` calls `AdcProtocol->GetChannel("BATT_THERM", 11, &ch)` (`AdcDxe.efi`) and `AdcRead` up to `10` times (stopping after `5` successes), drops min and max, averages the middle readings (defaulting to `300` = `30.0°C` if `0` reads succeed), and linearly interpolates the 23-point table at `0x8380`:
- Clamped `< 0` → `7000` (`700.0°C` fault), `< 0x4a8` (`1192`) → `900` (`90.0°C`), `>= 0x3af9` (`15097`) → `-200` (`-20.0°C`).
- Range `1191` (`90.0°C`) to `15097` (`-20.0°C`) in `5.0°C` (`50`-unit) steps (e.g., `8364` = `25.0°C`, `12907` = `0.0°C`).

### 3.6 Cross-Reference: `QcomChargerCfg.cfg` & `BATTERY.PROVISION`

Even though `extracted/F_XBL/cfg/uefiplat.cfg` (`DefaultChargerApp = "QcomChargerApp"`) and `extracted/F_XBL/cfg/{QcomChargerCfg.cfg, BATTERY.PROVISION}` are still shipped in the XBL FV:
- **`QcomChargerApp.efi` is NOT present** in `extracted/F_XBL/dxe/` or `apriori_order.json`, and no XBL DXE references `QcomChargerCfg` or `BATTERY.PROVISION`.
- `QcomChargerCfg.cfg` (`CfgVersion = 25`, `QcomChargerConfig_VbattTh_Sdm660.cfg`) contains Qualcomm's stock PMI8998/PM660 thresholds (`ChgFvMax = 4350` MTP / `4400` QRD, `ChgFccMax = 2000` / `3000`, `EmergencyShutdownVbatt = 3200`, `BootToHLOSThresholdInMv = 3600`, `LoadBatteryProfile = FALSE`).
- `BATTERY.PROVISION` contains three stock Qualcomm `[BATTERY_PROFILE]` blocks (`Ascent_with_connector_3450mAh_averaged_MasterSlave_Jan6th2017` @ `4350 mV`, `Batt_id=60000`, `Therm_B=3435`; `QRD8997_ST1031GA_3000mAh_averaged_MasterSlave_Jan10th2017` @ `4400 mV`, `Batt_id=68000`, `Therm_B=3380`; and `Itech_B00826LF_3000mAh_ver1660_averaged_MasterSlave_Jan10th2017` @ `4350 mV`, `Batt_id=100000`, `Therm_B=3435`).
- **Actual `SM-A920F` behavior**: Samsung replaced Qualcomm's PMIC/SMB charger stack with `Chg.efi` (`SM5705` charger + `SM5705` FG), using its own compiled-in `4350 mV` BATREG (`0x10fe`), FG model (`0x914a` / `0x918a`), `BATT_THERM` ADC LUT (`0x8380`), and ABL thresholds (`3450 mV` dead battery at `0x13b48`, `3100 mV` LPM pre-charge at `0x13464`, `3500 mV` low-battery gate at `0x138d4`).

---

## 4. `Vib.efi` — `SamsungVibratorProtocol` (`aa2e776d-8c9c-4268-998a-8b0a13bf0501`)

### 4.1 Vtable & ABL `100 ms` Boot Pulse (`0x1b280` & `0x1b164`)

`VibDxeEntry` (`0x1400`) installs `SamsungVibratorProtocol` at `0x60b0` (`0x10` bytes):

| Offset | Value / RVA | Method | Implementation | ABL Caller (`LinuxLoader.efi`) |
| --- | --- | --- | --- | --- |
| `+0x00` | `0x13c0` | `InitVib(UINT32 Rev, UINT32 Param2)` | `0x23f0` (`"vib_init : rev=%d\n"`, selects `COINDC` ops `0x60d8` → `0x2494`) | `0x1b280(1, 100, 0)` ← `0x1794` |
| `+0x08` | `0x13d8` | `SetVib(UINT32 Enable)` | `0x2458` (`"vib_onoff\n"`, normalizes `param_1 != 0` → `0x24e0`) | `0x1b280` (`SetVib(1)`) & timer callback `0x1b164` (`SetVib(0)`) |

- **Non-blocking `100 ms` boot pulse (`LinuxLoader.efi @ 0x1b280`)**:
  1. Creates a periodic/one-shot UEFI timer event (`gBS->CreateEvent(EVT_TIMER | EVT_NOTIFY_SIGNAL = 0x80000200, TPL_CALLBACK = 8, &LAB_0001b164, NULL, &DAT_0015cfc8)`).
  2. Calls `InitVib(1, 0)` (`*local_50`) then `SetVib(1)` (`local_50[1]`).
  3. Arms `gBS->SetTimer(event, TimerRelative = 2, 100 * 10000)` = `1,000,000` × `100 ns` = **`100 ms`**.
  4. When the timer fires, `0x1b164` locates `SamsungVibratorProtocol`, calls `SetVib(0)` (`x0 == 0` from `cbz x0` after `LocateProtocol`), and closes `DAT_0015cfc8`.

### 4.2 Hardware Control: S2DOS03 Companion PMIC `LDO4` (`3.3 V`)

Unlike Qualcomm PMIC haptic PWM drivers, `SM-A920F` drives a **coin DC vibration motor** (`"select coin dc motor driver\n"`) powered by **LDO4** on the **Samsung S2DOS03** display/companion PMIC over GPIO bit-banged I2C:
- **I2C Bus**: `s2dos03_i2c` (`0x56c0`), **SCL = GPIO `70` (`0x46`)**, **SDA = GPIO `66` (`0x42`)**, 8-bit slave **`0xc0`** (**7-bit `0x60`**).
- **`COINDC_vib_init` (`0x2494`)**:
  1. Calls `0x2e40` → registers `s2dos03_i2c` (`0x2fb4`) and reads S2DOS03 registers `0x00..0x05`, `0x10..0x13`, `0x20..0x21` (`0x3018`).
  2. Calls `s2dos03_set_voltage(3, 3300000)` (`0x2e7c`): index `3` selects **LDO4** (reg `0x10 + 3 = 0x13`), descriptor `0x6110` (`min = 600,000 uV`, `max = 3,775,000 uV`, `step = 25,000 uV`, `mask_shift = 7` → mask `0x7f`). Writes `(3300000 - 600000) / 25000 = 108` (`0x6c`) into S2DOS03 reg **`0x13`** (`LDO4_CTRL`), setting **`3.30 V`**.
  3. Reads back `s2dos03_get_voltage(3)` (`0x2edc`) and logs `"s2dos03 ldo4 voltage: %d\n"`.
- **`COINDC_vib_onoff` (`0x24e0`)**:
  - Uses shadow state `DAT_00006190` and modifies S2DOS03 **enable register `0x03`** bit `3` (`1 << 3 = 0x08`):
    - Enable (`0x2e54(3)`): `reg[0x03] = (reg[0x03] & ~0x08) | 0x08`
    - Disable (`0x2e68(3)`): `reg[0x03] = reg[0x03] & ~0x08`

---

## 5. `NpaLdo.efi` — `SamsungNpaLdoProtocol` (`6c3dbb2c-4354-4f5a-9e2f-40658db24402`)

### 5.1 Vtable & NPA Client Control (`0x13e4` → `0x2318` / `0x22e0`)

`NpaLdoDxeEntry` (`0x13e4`) installs `SamsungNpaLdoProtocol` at `0x50b0` (`0x10` bytes):

| Offset | Value / RVA | Method | Implementation | ABL Caller (`LinuxLoader.efi`) |
| --- | --- | --- | --- | --- |
| `+0x00` | `0x13a4` | `InitNpaLdo6(VOID)` | `0x2318` (`NPA_API_TEST_init`) | `0x1afa4` ← `0x1ada0` (`API_GPIO_TEST_RESET`) |
| `+0x08` | `0x13bc` | `SetNpaLdo6(UINT32 Enable)` | `0x22e0` (normalizes `param_1 != 0` to `1` or `0`) | `0x1b07c` ← `0x1ada0` (`1` before test, `0` after test) |

- **Consumed Protocol**: Locates Qualcomm **`NpaProtocol`** (`79d6c870-725e-489e-a0a1-27e7a5d0cb35` at `0x5090`, provided by `NpaDxe.efi`) via `0x2c60` and `0x2d0c`:
  - **`InitNpaLdo6` (`0x2318` → `0x2c60`)**: Invokes `NpaProtocol + 0x10` (`CreateSyncClientEx`) with resource name **`"/pmic/client/api_test"`** (backed by `DALSys.efi` node `"/node/pmic/client/api_test"`), client name **`"ApitestClient"`**, client type `0x40` (`NPA_CLIENT_REQUIRED`), storing the NPA client handle in `DAT_00005148`.
  - **`SetNpaLdo6` (`0x22e0` → `0x2d0c`)**: Invokes `NpaProtocol + 0x28` (`IssueScalarRequest`) on `DAT_00005148` with state **`1`** (ON) or **`0`** (OFF).
- **Board Peripherals Controlled (`LinuxLoader.efi @ 0x1ac44` + `0x1ada0`)**: During factory `API_GPIO_TEST_RESET` (when `FUN_0001890c() == 0`), ABL calls `InitNpaLdo6()` (`0x1afa4`), enables the LDO6 `1.8 V` rail via `SetNpaLdo6(1)` (`0x1b07c(1)`), stalls `10 ms` (`0x384f4(10000)`), configures and tests input levels on **10 `1.8 V` I2C peripheral lines** (touchscreen `TSP_SDA_1P8`/`TSP_SCL_1P8` GPIOs `14`/`15`; rear cameras `RCAM1_SENSOR_I2C` GPIOs `36`/`37`, `RCAM2_SENSOR_I2C` GPIOs `38`/`39`, `RCAM1_AF_EEP_I2C` GPIOs `6`/`7`, `RCAM4_AF_EEP_I2C` GPIOs `77`/`76`), and then powers the rail off via `SetNpaLdo6(0)` (`0x1b07c(0)`).
