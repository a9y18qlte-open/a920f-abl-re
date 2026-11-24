# Samsung Odin Protocol, Partitioning, Download Mode UI, and Verified Boot Architecture (`SM-A920F` ABL)

This report documents the Samsung Odin (Download Mode) USB protocol, PIT/GPT partition management, Download Mode status banner sources, and the Verified Boot / AVB / Samsung `Sec_Auth_*` / `Sec_Emc` verification pipelines in the Qualcomm SDM660 Android Bootloader (`abl`) for **Samsung Galaxy A9 2018 (`SM-A920F`, codename `a9y18qlte`, firmware `A920FXXS7CVH1`, SW_ID `000000070000001C`)**.

All RVAs are file offsets equal to virtual addresses (`ImageBase = 0x0`) in the unpacked PE32+ UEFI images:
- [`Odin.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/Odin.efi): `1,159,168` bytes, `.text` `0x1000..0x78000`, `.data` `0x78000..0x118000`, `.reloc` `0x118000..0x11b000` (`SHA-256: 96a77ec846ee258002b721ccb94e629f298862010b8f0890f59940dd0a19f5c8`)
- [`LinuxLoader.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/LinuxLoader.efi): `1,490,944` bytes, `.text` `0x1000..0x9f000`, `.data` `0x9f000..0x169000`, `.reloc` `0x169000..0x16c000` (`SHA-256: a67caa9a8d7d4b7f8cfdd5bd847b252b384e77b77bf3c7b770d1366559245b25`)

Constants, jump tables, partition tables, UI strings, and cryptographic key hashes in this document are verified by [`analyze_odin_protocol.py`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/scripts/analyze_odin_protocol.py).

---

## 1. `Odin.efi` Lifecycle & USB Transport (`OdinMain.c`)

### 1.1 Entry & Initialization Flow
1. **UEFI Entry (`_ModuleEntryPoint` @ `0x1000`)**: [`001000_entry.c`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/decomp/F_Odin/funcs/001000_entry.c) initializes EDK2 libraries via `FUN_000010ac` (`ProcessLibraryConstructorList`), invokes `FUN_00001574` -> `FUN_00001dec` (`OdinMain`), and exits through `FUN_00001444`.
2. **`OdinMain` (`FUN_00001dec` @ `0x1dec`)**:
   - Logs build timestamp (`Aug 26 2022 19:11:41`) and initializes stack canary entropy (`FUN_0000a188`).
   - Calls `FUN_00001634` (`UsbDeviceInit`) to bring up USB transport and register Odin commands.
   - Resets/initializes `param` state (`FUN_0001db38`, `FUN_0001db94`, `FUN_0001cde0`), sets display backlight to `10`, and renders the Download Mode background and status banner (`FUN_0001acd4` -> `FUN_0001b2c8`).
   - Checks build variant via `FUN_0000d0f8("user", "eng")`, invokes `FUN_0001b688` (BoardInfo dump) or `FUN_0001b5f0` (carrier/footer UI), and calls `FUN_00014320` -> `FUN_00013e0c` (`SecureWP` / write-protect initialization).
   - Enters the main Download Mode event loop: polls USB events via `FUN_00001c5c` and keypad input via `FUN_0001fb7c` (keys `1`/`2` toggle screen brightness between `0xff` and `10`) until the exit flag `DAT_000fc9f6` (`FUN_0000400c`) becomes non-zero.
   - On exit, `FUN_0000404c` frees the `0x40000000` (1 GiB) Odin staging buffer via `UsbDeviceProtocol+0x28`, closes `0x1000` `BlockIo2` async events, stops the USB controller via `UsbDeviceProtocol+0x30`, and frees RX/TX USB buffers.

### 1.2 Watchdog, Memory Buffers & UEFI USB Function Protocol
- **USB Controller & Protocol Binding (`FUN_00001634` @ `0x1634`)**:
  - Signals the Qualcomm USB controller initialization event GUID `d9d9ce48-44b8-4f49-8e3e-2a3b927dc6c1` (`0x552e8`).
  - Locates the UEFI USB device protocol `1c0cffce-fc8d-4e44-8c78-9c9e5b530d36` (`0x552f8`, `QcomUsbfnOrDeviceProtocol`) into `DAT_000fc960`.
  - Calls `FUN_0000414c` (`CmdsInit`), builds USB descriptors via `FUN_000020b4`, starts the USB controller via `UsbDeviceProtocol+0x48` (`UsbDeviceStart`), and allocates two `0x100000`-byte (`1 MiB`) DMA-capable buffers via `UsbDeviceProtocol+0x20`:
    - `DAT_000fc968`: `1 MiB` bulk OUT (RX) buffer
    - `DAT_000fc970`: `1 MiB` bulk IN (TX) buffer
- **`CmdsInit` (`FUN_0000414c` @ `0x414c`)**:
  - Disables the UEFI firmware watchdog: `gBS->SetWatchdogTimer(0, 0x10000, 0, 0)`.
  - Allocates/creates `0x1000` UEFI events at `DAT_000fca08` for asynchronous `BlockIo2` flashing (`FUN_000046bc`).
  - Enumerates storage partitions via `FUN_00020390`.
  - Allocates the `0x40000000`-byte (`1 GiB`) Odin download staging buffer into `DAT_000ffc90`.
  - Registers the 5 ASCII command handlers (`"ODIN"`, `"ATQ0"`, `"ROOTING"`, `"DVIF"`, `"SECCMD"`) into linked list `DAT_000ffc98`.

### 1.3 USB Descriptors & Endpoint Transfers (`FUN_000020b4`, `FUN_00001c5c`)
- **Descriptors (`FUN_000020b4` @ `0x20b4`)**:
  - High-Speed Device Descriptor (`0x78038`) and SuperSpeed Device Descriptor (`0x7804a`) both advertise **VID `0x04e8`** (Samsung Electronics) and **PID `0x685d`** (Samsung Download/CDC ACM device).
  - Interface `0` is CDC Control (`0x02`/`0x02`/`0x01`) with Interrupt IN endpoint `0x82` (`16`B max packet).
  - Interface `1` is CDC Data (`0x0a`/`0x00`/`0x00`) with **Bulk OUT endpoint `0x01`** and **Bulk IN endpoint `0x81`** (`512`B max packet for HS at `0x78092`/`0x78099`; `1024`B max packet for SS at `0x780dc`/`0x780e9`).
  - USB string descriptors (`0x78010` table -> `0x5570e`, `0x55712`, `0x5572c`, plus serial buffer `DAT_000fc9b8`) report `"Samsung"`, `"SDM660"`, `"odin"`, and the UFS/eMMC serial number.
- **USB Event Polling (`FUN_00001c5c` @ `0x1c5c`)**:
  - Calls `UsbDeviceProtocol+0x18` (`HandleEvents`).
  - On USB connect/enumeration (`event == 1`, `state == 0`), queues a Bulk OUT receive of `0x1ff` bytes on endpoint `1` into `DAT_000fc968`.
  - On endpoint `1` transfer completion (`event == 2`, `(ep & 0xf) == 1`), dispatches Bulk IN completions (`(int8_t)ep < 0`) to `FUN_00001ae8` (which handles TX continuation up to `0x1000000` via `FUN_00002770` and protocol ZLP/IN pacing) and Bulk OUT completions to `FUN_000019ec` -> `FUN_00003e98` (ASCII command dispatcher).
  - Synchronous TX formatting (`FUN_000027ac` @ `0x27ac`) transmits responses on Bulk IN endpoint `0x81` via `UsbDeviceProtocol+0x10`.

---

## 2. Complete Odin / Loke Wire Protocol (`OdinProtocol.c`, `PitUpdate.c`)

### 2.1 Top-Level ASCII Handshake Commands (`CmdsInit` `0x414c`, `0x3e98`)
Before entering the binary 1024-byte Odin/Loke state machine, `FUN_00003e98` matches incoming Bulk OUT strings against the linked list `DAT_000ffc98` (falling back to `"unknown command"` via `0x27ac`):

| ASCII Command | Handler RVA | Behavior & Wire Response (EP `0x81`) |
|---|---|---|
| `ODIN` | `0x047b4` | Replies `"LOKE"` (4 bytes) on EP `0x81`, then enters the synchronous 1024-byte binary Odin/Loke loop calling `FUN_00007120`. |
| `ATQ0` | `0x067d0` | Handshake ping; replies `"OKAY"`. |
| `ROOTING` | `0x06848` | Replies `"DDI"` (Device Diagnostic Information). |
| `DVIF` | `0x068c0` | Queries device/DDI/param/UFS fields and returns `@#MODEL=...;UN=...;CAPA=...;VENDOR=...;FWVER=...;PRODUCT=...;PROV=...;SALES=...;VER=...;DID=...@#`. |
| `SECCMD` | `0x06f98` | Subcommand `'1'` calls `FUN_0001317c` to set the Knox Warranty Bit (cmd `0x1` to `bksecapp`) if RP is disabled and device is non-ARP. |

### 2.2 Binary 1024-Byte Frame & Dispatch Tables
Once `"ODIN"` receives `"LOKE"`, `0x4a14` clears a `0x400`-byte (`1024`-byte) stack buffer, receives `0x400` bytes synchronously via `FUN_00007120`, and copies it to `[sp, #0x480]`:
- `[sp + 0x480]` (`uint32_t`): **`cmd`** (`0x64..0x69`)
- `[sp + 0x484]` (`uint32_t`): **`subcmd`**
- `[sp + 0x488..]` (`uint32_t[]` / payload): command arguments (e.g., byte count, sequence index, partition ID, special ID flag, SalesCode)
- **Standard ACK/Response**: 8-byte little-endian packet `[uint32_t cmd_or_status, uint32_t arg]` sent over Bulk IN `0x81`.

Main jump table at `0x55830` (6x `uint64_t` RVAs indexed by `cmd - 0x64`):

| `cmd` | Handler RVA | Subcommand Table | Purpose |
|---|---|---|---|
| `0x64` | `0x04a54` | `0x55880` (`0x0..0xa`) | Session start, progress total, USB packet size, userdata/debug erase, SalesCode, Sprint RTN |
| `0x65` | `0x04b00` | `0x55860` (`0x0..0x3`) | PIT flash/dump/re-partition (`PitUpdate.c`) |
| `0x66` | `0x04b68` | Inline switch (`0x0, 0x2, 0x3`) | Data transfer (`XmitData`) and flashing (`0x7360`) |
| `0x67` | `0x04bb8` | Inline switch (`0x0` vs `!=0`) | End session, boot partition restore, target reset / reboot into Odin |
| `0x68` | `0x04c94` | — | Undefined / error path (`0x45d0`) |
| `0x69` | `0x04ccc` | Inline switch (`0x0..0x2`) | Binary `DevInfo` struct query & chunked read |

#### Subcommand Breakdown (`0x64`, `0x65`, `0x66`, `0x67`, `0x69`)

| `cmd` | `subcmd` | Handler RVA | Semantics & Request / Response Details |
|---|---|---|---|
| `0x64` | `0x00` | `0x04a78` | **SessionStart**: Negotiates Odin version from `[sp+0x488]` (`0x20000` v2 default, `0x30000` if `>= 3`); logs `"Odin Version : %d\n"`, replies `[0x64, version]`. |
| `0x64` | `0x01` | `0x0567c` | **GetParam / MaxChunk**: Replies `[0x64, 0x1e]` (`30`). |
| `0x64` | `0x02` | `0x056b8` | **TotalBytes**: Initializes total expected transfer byte counter (`DAT_000ffc58`) for UI progress bar, replies `[0x64, 0]`. |
| `0x64` | `0x05` | `0x05760` | **SetPacketSize**: Sets USB transfer chunk size at `DAT_00078638` (`[0x78638]`), replies `[0x64, 0]`. |
| `0x64` | `0x07` | `0x057a4` | **Factory / Userdata Erase**: Calls `FUN_00007220("userdata")` (erases partition + calls `FUN_0001f8c0` to reset VB device state) or clears debug level (`0x1d83c`). |
| `0x64` | `0x09` | `0x057f0` | **Set SalesCode**: Updates SalesCode via `FUN_0001d244`, replies `[0x64, 0]`. |
| `0x64` | `0x0a` | `0x05868` | **Set RTN_CONFIG**: Sprint carrier codes (`SPR`/`BST`/`VMU`/`XAS`) via `FUN_0001d328`. |
| `0x64` | `0x03,0x04,0x06,0x08` | `0x04a14` | Unused / no-op loop continuation. |
| `0x65` | `0x00` | `0x04b28` | **PIT Flash Init**: Prepares staging buffer for incoming PIT upload, replies `[0x65, 0]`. |
| `0x65` | `0x01` | `0x05910` | **PIT Dump Init**: Reads on-disk PIT (`0x3000` bytes) via `FUN_000085e0`, replies `[0x65, 0x3000]`. |
| `0x65` | `0x02` | `0x05984` | **PIT Dump Part**: Sends `500`-byte slice indexed by `[sp+0x488]` (up to `0x3000` total) on EP `0x81`. |
| `0x65` | `0x03` | `0x05a10` | **PIT Complete**: Verifies `"pit"` via `Sec_Auth_Odin` (`0x00e6ec`), writes `0x3000`-byte PIT, runs `PitUpdate` (`0x008ca4`), and restores backed-up boot partitions (`0x780f8` table). |
| `0x66` | `0x00` | `0x04b80` | **XmitInit**: Resets transfer offsets/state for an incoming image, replies `[0x66, 0]`. |
| `0x66` | `0x02` | `0x050e8` | **XmitData**: Receives `len < 0x20000000` (`512 MiB` max per `0x66/0x02` block) into the `1 GiB` staging buffer (`DAT_000ffc90`) in `[0x78638]`-sized USB chunks; replies `[0, seq]` after each chunk. |
| `0x66` | `0x03` | `0x0501c` | **XmitComplete**: Invokes `FUN_00007360` to authenticate and flash the staged image (`[sp+0x488] == 0` -> standard/sparse partition by PIT ID; `== 1` -> special ID partition via `FUN_00003c48`). |
| `0x67` | `0x00` | `0x04e28` | **EndSession**: Logs elapsed time & transfer speed, clears progress, flags `RebootRecoveryAfterOdinDL` if `DAT_000fc9f7` is set, calls `FUN_0001d1a0(1)`. |
| `0x67` | `!= 0` (`1`) | `0x04bc0` | **Reset / Reboot**: Restores buffered boot partitions if dirty, then switches on `[sp+0x484]`: `0` = XmitCompleted ACK, `1` = TargetReset (`0x1e998(0/1)`), `2` = RebootIntoOdin (`0x1e998(2)`). |
| `0x69` | `0x00` | `0x04ce4` | **DevInfo Init**: Populates `DAT_000ffa10` with header (`0x55800` template: magic `0x12345678`, 3 records), UFS/eMMC capacity/vendor/serial, `"SM-A920F"`, SalesCode; replies `[0x69, total_size]`. |
| `0x69` | `0x01` | `0x05348` | **DevInfo Read**: Sends `500`-byte slice `[sp+0x488] * 500` from `DAT_000ffa10` on EP `0x81`. |
| `0x69` | `0x02` | `0x05310` | **DevInfo End**: Completes DevInfo transfer, replies `[0x69, 0]`. |

### 2.3 Image Flashing, Sparse Images, Special IDs & Boot Partition Backup (`0x7360`, `0x3604`, `0x3c48`, `0x80ac`)
- **Pre-Write Checks (`FUN_00007360` @ `0x7360`)**:
  - Rejects direct Odin flashing of `"md5"`, `"sgpt"`, `"pgpt"`, and `"pit"` via `0x66` (PIT must go through `0x65`).
  - If partition is `"steady"` and size `<= 0x1000`, forwards to the EMC token verifier (`FUN_00018534` / `FUN_00018ea4`).
  - Runs `Sec_Auth_Odin` (`FUN_0000e6ec`) and Enhanced Security Check (`FUN_0000fff4`) before any write.
  - Flashing `"cache"` triggers an erase of `"misc"`.
- **Android Sparse Image Unpacking (`FUN_00003604` @ `0x3604`, `FUN_000028b0` @ `0x28b0`)**:
  - Triggered when the payload starts with Android sparse magic **`0xed26ff3a`** (`-0x12d900c6`).
  - Parses the `0x1c`-byte `sparse_header_t` and `0x0c`-byte `chunk_header_t` entries: `0xcac1` (`CHUNK_TYPE_RAW`), `0xcac2` (`CHUNK_TYPE_FILL`), `0xcac3` (`CHUNK_TYPE_DONT_CARE`), and `0xcac4` (`CHUNK_TYPE_CRC32`).
  - Buffers the first `4096` bytes (`0x1000`, LBA 0 ext4 superblock) in `DAT_000ffc88` and writes LBA 0 only upon final block completion (`DAT_000ffc10 == DAT_000ffc78`), preventing partially flashed filesystems from appearing mountable.
  - Supports multi-`XmitData` sparse streams (`return 4` when a chunk spans USB `XmitData` boundaries, with `0x7c40000`/`0x1e00000` staging offset tracking).
- **Special ID Flashing (`HandleSpecialIdFlash` `FUN_00003c48` @ `0x3c48`)**:
  - Invoked when `[sp+0x488] == 1` and `part_id > 0x45`. Reads UFS LUN from `param_3 + 0x1c`, start LBA from `param_3 + 0x14`, and max block count from `param_3 + 0x18`, writing directly via `FUN_000201a4`.
- **Boot Partition RAM Backup (`CheckBootPartition` `FUN_000080ac` @ `0x80ac`)**:
  - Before repartitioning GPT in `0x65/0x03`, `Odin.efi` buffers `14` critical partitions listed in the `0x60`-stride table at **`0x780f8`** (`xbl`, `rpm`, `tz`, `hyp`, `pmic`, `abl`, `devcfg`, `cmnlib`, `cmnlib64`, `keymaster`, `apdp`, `sec`, `bksecapp`, `btd`) and re-writes any partition whose GPT LBA changed.

### 2.4 PIT Binary Format vs. GPT Translation (`PitUpdate.c`)
- **PIT Storage & Header (`0x83d4`, `0x85e0`, `0x883c`, `0x8918`, `0x8ca4`)**:
  - Fixed PIT buffer size: **`0x3000` bytes (`12 KiB`)**, located at **LBA `6`** on UFS LUN 0 or **LBA `0x22`** on eMMC.
  - Header (`0x1c` bytes): magic **`0x12349876`**, entry count, `"COM_TAR2"` tag (`8` bytes), and CRC32 validation.
  - Partition entries: **`0x84` (`132`) bytes** each (including PIT `id`, `bin_type`, `dev_type`, `attribute`, `start_lba`, `num_blocks`, `file_offset`, `file_size`, `partition_name[32]`, `flash_filename[32]`, `fota_filename[32]`).
- **PIT-to-GPT Synthesis (`FUN_00008ca4` -> `FUN_00020908` @ `0x20908`)**:
  - `Odin.efi` embeds a **`62`-entry** (`0x58`-byte stride: `char name[72]` + `EFI_GUID type_guid`) lookup table at **`0x7863c..0x79b8c`** mapping Samsung PIT partition names (`modemst1` at index 0 through `persistent` at 59, `GPT` at 60, `linux` at 61) to Qualcomm/Android GPT Partition Type GUIDs.
  - Synthesizes a Protective MBR, Primary GPT header + entries, and Backup GPT header + entries across all target UFS LUNs (`0..N`) / eMMC user area, then restores the `14` buffered boot partitions (`0x780f8`).

---

## 3. Download Mode UI & Status Banner

The Download Mode screen combines three embedded JFIF JPEG tile assets (`0x7aad4`, `0xa5e18`, `0xb26f4`, rendered by `Glib.c` `FUN_0001ad44` for static graphics like `"ODIN MODE"`, `"PRODUCT NAME"`, `"SYSTEM STATUS"`, `"Downloading... Do not turn off target"`) with dynamic lines drawn via `FUN_0001a8e8` inside `FUN_0001b2c8` (`0x1b2c8`), `FUN_0001b5f0` (`0x1b5f0`), and `FUN_00018fb4` (`0x18fb4`).

Dynamic values come from the global `DevAuth` structure **`DAT_0007a528`** (populated in `FUN_0000f138` @ `0xf138` and returned by `FUN_0000f0e0` @ `0xf0e0`):

| UI Status Line (`FUN_0001a8e8` Format String @ RVA) | `Odin.efi` Reader / Offset | Backing Storage / Source |
|---|---|---|
| `CURRENT BINARY: %a` (`0x5b573`) | `FUN_000119ac` (`0x119ac`) | **`btd` partition** (`last_lba - 1`, `0x160`-byte DDI struct at `DAT_0010bff0`, magic `0x12340012`; `DAT_0010bffc`: `0`=`Samsung Official`, `(val & 0xf) != 0`=`Custom`, else `Unknown`). |
| `FRP LOCK : %a` (`0x5b587`) | `DevAuth+0x30` (`DAT_0007a558` <- `0x13d2c`) | **`persistent` partition** (`DAT_0010c150` populated in `0x13e0c`; prints `"ON"` at `0x62174` only when `FRP != 0 && OEM == 0`, else `"OFF"` at `0x5b596`). |
| `OEM LOCK : %a` (`0x5b59a`) | `DevAuth+0x34` (`DAT_0007a55c` <- `0x13b7c`) | **`persistent` partition** (`DAT_0010c154` populated in `0x13e0c`; prints `"ON"` at `0x62174` when `OEM == 0`, `"OFF"` at `0x5b596` when `OEM != 0`). |
| `RMM STATUS : %a` (`0x5b5a9`) | `DevAuth+0xc4` (`DAT_0007a5ec` <- `0x19a40`) -> `0x19ddc` | **`steady` partition** (offsets `0x7d000` / `0x7e400`; hidden if `-0x34343500` `Allzero`, `-0x34343435` `Broken`, or `-0x34343401`; otherwise `Prenormal`, `Normal`, `Locked`, `Blink`, `Completed`). |
| `KG STATUS : %a` (`0x5b5ba`) | `DevAuth+0xc8` (`DAT_0007a5f0` <- `0x1a19c`) -> `0x1a554` | **`steady` partition** (offsets `0x7f800` / `0x82000`; hidden if `Allzero`/`Broken`/`-0x34343401`; otherwise `Prenormal`, `Normal`, `Locked`, `Blink`, `Completed`, `Checking`). |
| `WARRANTY VOID : 0x%x` / `0x%x (0x%x)` (`0x5b5eb`/`0x5b5ce`) | `DevAuth+0x50` (`DAT_0007a578` <- `0x10818`), `DevAuth+0x8c` (`DAT_0007a5b4` <- `0x130fc`) | **`bksecapp` TZ/RPMB cmd `0x0`** (and `DAT_0010c04c` warranty history). Suppressed when `0x1d9e0` carrier == `"VZW"`. |
| `QUALCOMM SECUREBOOT : ENABLE` / `NONE` / `0x%x` (`0x5b601`/`0x5b678`/`0x5b63f`) | `DevAuth+0x00` (`DAT_0007a528` <- `0x109ac`) | **`bksecapp` TZ cmd `0xb`** (`0`=`NONE`, `0xf`=`ENABLE`, else hex). |
| `RP SWREV : B%d(%d,%d,%d,%d,%d) K%d S%d` (`0x5b6d7`) | `DevAuth+0x04`, `+0x14..+0x2c`, `+0x0c`, `+0x10` | **`bksecapp` TZ cmds `0xd..0x13`** (XBL, PIL/Modem, RPM, TZ, HYP, AP, Kernel/System) + `0x14fcc`/`0x14f90`; printed only when `DevAuth+0x04` (`bksecapp` cmd `0x7` RP enabled) != `0`. |
| `RP SWREV : TEST DEVICE` (`0x5b6ff`) | `DevAuth+0x08` (`DAT_0007a530` <- `0x10d0c`) | **`bksecapp` TZ cmd `0x8`** (Anti-Rollback Protection disabled / test device flag). |
| `SECURE DOWNLOAD : ENABLE` (`0x5b717`) | Unconditional in `0x1b5b0` | Hardcoded whenever Download Mode UI is drawn (`0x1b5b0..0x1b5bc`). |
| `ENG MODE : DEV DEVICE` / `* ALLOWED(%a)` (`0x18fb4`) | `DAT_0010c278` / `DAT_0010c27c` / `DAT_0007aa28` | **`Sec_Emc.c` (`0x15dec`)**: `"ENGRES0001"` + `"FUSE"` in **`steady`** (`0x2`=`ENG`, `0x10`=`CUSTOM`, `0x40`=`KNOX TEST`). |
| `DID : %a` (`0x18fb4`) | `DAT_0010c280` (else `0x1ec64`/`0x1f38c` ChipID `%04x%08x` @ `0x5a911`) | **`steady`** / SoC ChipInfo unique ID. |
| `CARRIER : %a` (`0x1b5f0`) | `FUN_0001d968` | Shown when region check (`0xd308("USA","EUR")`) matches. |

> **Note on `bksecapp` IPC (`0x1063c` in `Odin.efi`, `0x8994` in `LinuxLoader.efi`)**: Both images communicate with Samsung's `bksecapp` TrustZone applet via `QcomScmOrTzProtocol` using a `0x138`-byte request/response struct (`DAT_0010bea0` / `DAT_0007a758` in `Odin.efi`, `DAT_00157e04` / `DAT_0009fbe8` in `LinuxLoader.efi`), with command ID at `+0x00` and return status at `+0x134`.

---

## 4. Verified Boot, Samsung `Sec_Auth_*` & AVB Architecture

### 4.1 Boot-Time Image Loading & Android Verified Boot (`LinuxLoader.efi` `0x2154`)
`FUN_00002154` (`LoadImageAndAuth`) orchestrates Android boot (`boot` / `recovery` / `dtbo`):
1. Locates Qualcomm Verified Boot protocol (`gGuid_QcomTokenSpaceGuid_CAF`) via `gBS->LocateProtocol` into `param_1 + 0x430`, and allocates a `0x400`-byte VB cmdline buffer (`param_1 + 0x440`).
2. Loads `boot` or `recovery` (`0x1f318` -> `0x251bc` -> `0x1ee3c` boot image header parsing) and, if present, loads `dtbo` using an instantiated **`AvbOps`** structure (`FUN_0000452c` @ `0x452c`, size `0x58` bytes):
   - `AvbOps+0x18` (`0x3294`): `read_from_partition` (supports negative offsets from partition end)
   - `AvbOps+0x20` (`0x3b48`): `get_preloaded_partition` (stub returning `2` / `AVB_IO_RESULT_ERROR_IO`)
   - `AvbOps+0x28` (`0x3b84`): `validate_vbmeta_public_key` — checks `GetUserKey` (`0x2b19c`) OR the built-in **OEM AVB RSA-4096 public key** (`AvbRSAPublicKeyHeader` at **`0x76cfb`**, `0x408` bytes, `key_num_bits = 4096`, `n0inv = 0x55d904ad`)
   - `AvbOps+0x30` (`0x3db0`): `read_rollback_index` (via `0x2af74` `ReadRollbackIndex` in `devinfo`)
   - `AvbOps+0x38` (`0x3e78`): `write_rollback_index` (updates `0x2b068` only if current slot is bootable via `0x28e50`)
   - `AvbOps+0x40` (`0x3fc0`): `read_is_device_unlocked` (via `0x2ad68` from `devinfo`)
   - `AvbOps+0x48` (`0x4044`): `get_unique_guid_for_partition`
   - `AvbOps+0x50` (`0x4440`): `get_size_of_partition` (`(last_lba + 1) * block_size`)
3. Appends `root=` if missing (`0x25d54`) and sends the TZ **Milestone** SCM call via `(*(param_1 + 0x430) + 0x20)()`.

### 4.2 Samsung `SignerVer01` / `SignerVer02` & `Sec_Auth_*` (`Odin.efi` & `LinuxLoader.efi`)
Both `LinuxLoader.efi` (`Sec_Auth_Kernel.c` `0x6ba4`, `Sec_Auth_Odin.c` `0x80c8`) and `Odin.efi` (`Sec_Auth_Odin.c` `0xe6ec`, `0xfff4`) implement Samsung's proprietary image authentication alongside Qualcomm Secure Boot and AVB:

1. **Footer / Signature Block Parsing (`0x149d4` in `Odin.efi`, `0x0cfa4` in `LinuxLoader.efi`)**:
   - For standard partitions (`type != 0xe`), reads the `0x200`-byte footer at `image_end - 0x200` and the `0x100`-byte RSA-2048 signature at `image_end - 0x100` (`0x0d1a0`).
   - For sparse filesystem images (`type == 0xe`), reads the `0x100`-byte signature immediately after the `0x300`-byte Samsung sparse-auth header (`page_size`-aligned at `lVar3 + hdr_8 + hdr_10`), and the `SignerVer02` metadata block `+0x300` bytes past that (`lVar3 + hdr_8 + hdr_10 + 0x300`).
   - Recognizes magic **`"SignerVer01"`** (`1`) or **`"SignerVer02"`** (`2`). In `SignerVer02`, extracts the image release/build tag (`"fac"`, `"mrk"`, `"usr"`, `"eng"`, `"knx"` via `0x14900` / `0x0ced0` at `puVar4 + 0x12` and `puVar4 + 0x13`) and stores the `0x100`-byte `SignerVer02` block at `DAT_0010c16d` (`Odin.efi`) / `DAT_001580b8` (`LinuxLoader.efi`).
2. **RSA-2048 Signature & `SEANDROIDENFORCE`**:
   - Verifies SHA-256 of the image body (`param_2 - 0x100`) using `QcomHashOrVbProtocol` / `QcomSecurityHashProtocol` against the PKCS#1 v1.5 RSA-2048 decrypted signature using the **identical embedded `294`-byte (`0x126`) DER `SubjectPublicKeyInfo` key**:
     - [`Odin.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/Odin.efi) @ **`0x5b1dc`** == [`LinuxLoader.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/LinuxLoader.efi) @ **`0x7a05b`** (`SHA-256: a36d209b23ff5b7d9ece24bce8ff0fdbd01806643342781be51f95d1df6aa4b0`).
   - On `LinuxLoader.efi` kernel boot (`0x6ba4`), additionally invokes **`0x008dc8`** (`bksecapp` command `0xc` `[TIMA trusted boot]: Boot-time measurement`), extracts `boot`/`kernel` build numbers (`puVar5[0x27]`, `puVar5[0x28]`), and hashes the RSA key into `puVar5 + 0x29` when authenticated. (`SEANDROIDENFORCE` is handled/logged as part of Samsung kernel/recovery footer conventions around `Sec_Auth_Kernel.c`.)
3. **Partition Policy Table (`Odin.efi` @ `0x79ba8`)**:
   - `37` named partition entries (`stride 0x40`, terminated by empty string entry `[37]` at `0x7a4e8`):
     - `type 10` (`Bootloader`): `xbl`, `xbl_config`, `aop`, `rpm`, `tz`, `hyp`, `sec`, `pmic`, `abl`, `bksecapp`, `vk`, `em`, `storsec`, `keymaster`, `cmnlib`, `cmnlib64`, `apdp`, `msadp`, `qupfw`, `pit`, `devcfg`, `apnhlos`, `misc`
     - `type 11` (`Kernel`): `boot`
     - `type 12` (`Recovery`): `recovery`
     - `type 13` (`Modem`): `modem`
     - `type 14` (`Sparse`, sparse flag = `1`): `system`, `vendor`, `cache`, `userdata`, `omr`, `odm`, `hidden`, `carrier`, `persist`, `efs`, `dqmdbg`

### 4.3 Enhanced Security Policy (`0x00fff4` in `Odin.efi`, `0x0080c8` in `LinuxLoader.efi`)
After signature verification (`AUTHENTICATE`, reason `1`), Enhanced Check (`ENHANCED`, reason `2`) enforces all device lock & anti-rollback policies (error enum table at `0x7a678`):
- **Rollback Prevention (`RP SWREV`)** (`0x157e0` in `Odin.efi`, `0x00d5d8` in `LinuxLoader.efi`): Compares fused `bksecapp` counters (`0xd..0x13`) against the incoming binary's `SWREV` (`KERNELSYSTEMRP` = `10`, `BOOTRP` = `11`, `SW REV CHECK FAIL : [%a]Fused %d > Binary %d` or `"not official"`).
- **Carrier / Cross-Download (`CROSSDOWNLOAD` = `9`)**: Rejects mismatched carrier/binary policies.
- **Lock States**:
  - `MDMPolicy` (`3`): `DAT_0010bd8e==2 && DAT_0010bd8f==6 && DAT_0010bd77==8` (`0x10340` `[MDM]`).
  - `ENGINEERMODE` (`5`): Unofficial (`ENG`/`KNOX TEST`/Unknown) binaries blocked unless authorized by `Sec_Emc`.
  - `FRPLOCK` (`6`): Blocks custom kernel/recovery/system binaries when Factory Reset Protection is active (`persistent`).
  - `REACTIVATIONLOCK` (`7`) & `KIWILOCK` (`8`, C-ROM Lock): Blocks custom binaries; C-ROM Lock (`0x00fed4` / `0x007f3c`) triggers a dedicated red warning halt until power-off.
  - `OEMLOCK` (`12`): Blocks custom `boot`/`recovery`/`system` when OEM unlock is off.
  - `RMM` (`13`) & `KNOXGUARD` (`14`, `KG`): Blocks custom or all binaries depending on `steady` state (`Locked` `-0x343434fa`, `Prenormal` `-0x343434fe`, or installment-balance non-normal states).
- **Knox Warranty Bit (`0x1`)**:
  - Booting or flashing non-official `boot`/`recovery`/`system` (when allowed by unlock/OEM unlock and not suppressed by `FRP` test-bit) permanently trips the warranty fuse via `bksecapp` command `0x1` (`0x108e0` in `Odin.efi`, `0x008c38` in `LinuxLoader.efi`, logging `"[TIMA boot measurement] : Old/non-CL device - KNOX warranty void"`), sets `DDI` (`btd`) to `Custom` (`0x119ac`), and sets `androidboot.verifiedbootstate` (`0x7054` `PTR_s_green_0009fa60` -> `["green", "yellow", "orange", "red"]` indexed by `DAT_0009fa80`, where `2` = `"orange"`) and `androidboot.warranty_bit=%d` in `sec_update_cmdline` (`0x706bc`).
- **Write Protect**: Checked/enforced by `FUN_00013e0c` (`Odin.efi`) and `FUN_0006f444` (`LinuxLoader.efi` `[SYS WP]`, `[SW WP]`).

### 4.4 Samsung Engineering Mode Token Verification (`Sec_Emc.c`, `0x15dec` in `Odin.efi`)
Samsung's Emergency/Engineering Mode (`Sec_Emc.c`) permits authorized service tokens stored in the **`steady`** partition to unlock `ENG`, `CUSTOM`, or `KNOX TEST` binary acceptance without tripping normal unsigned-binary rejection:
1. Reads the EMC block from `steady` (`"ENGRES0001"` / `"FUSE"` marker).
2. Verifies token signature and certificate sizes (`0x100`-byte RSA-2048 signature header at `+0x2f` short check, cert length `1..0xf41` bytes at `+0x1bf`, DER X.509 cert at `+0x1c1`).
3. Parses and decrypts the certificate signature against the embedded **EMC Root RSA-2048 public key** (`294`-byte DER SPKI: [`Odin.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/Odin.efi) @ **`0x5a670`** == [`LinuxLoader.efi`](file:///home/thongass000/.gemini/antigravity-cli/scratch/a920f-abl-re/extracted/F/LinuxLoader.efi) @ **`0x795f0`**, `SHA-256: cde6a83f2e567c4611e215bd773e9d86621d15ca45904c5449fba6f9f4ceec06`), verifying the SHA-256 digest (accepting `0x20` raw or `0x33` DigestInfo-prefixed RSA output) and checking that the X.509 Common Name (`CN`) via `0x15aec` equals **`"EngineeringMode"`**.
4. Extracts the leaf `X.509` public key (`0x34374` -> `0x387f8` -> `0x33d00`) and verifies the SHA-256 signature over the `0xb2`-byte token body (`0x31df4`).
5. Calls `FUN_00018594` (`T-U` device binding check) to validate the device's `DID` and unlock bits (`+0xb9`):
   - `bit 3` (`(b >> 3) & 1`): **CUSTOM allowed** (`DAT_0010c27c = 0x10`)
   - `bit 0` (`b & 1`): **ENG allowed** (`DAT_0010c27c = 2`)
   - `bit 4` (`(b >> 4) & 1`): **KNOX TEST allowed** (`DAT_0010c27c = 0x40`)
6. Copies the authorized model string into `DAT_0007aa28` for display (`FUN_00018fb4`) and passes `androidboot.em.did`, `androidboot.em.model`, and `androidboot.em.status` to the Linux kernel via `sec_update_cmdline` (`0x706bc`).
