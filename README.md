# SM-A920F (`a9y18qlte`) ABL, XBL & `bksecapp` Reverse Engineering

Comprehensive static reverse engineering of the Samsung Galaxy A9 (2018) (Qualcomm SDM660) bootloader chain: **`abl.elf`** (`SM-A920F` `A920FXXS7CVH1`, `SM-A920N` `A920NKSU5CVG1`, `SM-A9200` `A9200ZHU5CZB1`), **`xbl.elf`** (`XBL_Loader`, `XBL_Ramdump`, `Sec.te`, and UEFI DXE drivers), and **`bksecapp.mbn`** (`APP_ID=0x888`).

> **Address Convention**: All PE32+ UEFI applications/DXEs (`Odin.efi`, `LinuxLoader.efi`, and XBL DXE drivers) use `ImageBase = 0x0`, so `VA == RVA == FileOffset`. `LinuxLoader.efi` and `Odin.efi` enter at `0x1000`; XBL DXE drivers enter at `0x1130`.

## Directory Layout

- `docs/` — Detailed technical reverse-engineering reports:
  - **Phase 1 — ABL (`LinuxLoader.efi` & `Odin.efi`)**:
    - `docs/01-uefi-architecture-and-bootflow.md` — `abl.elf` ELF64/MBN v5/`SignerVer02`/FV container anatomy, `xbl_uefiplat.cfg` DDR map, EDK2 constructors & globals, full UEFI Protocol/Variable inventory, boot-mode & reset-reason state machine, `BoardInfo.c`, and `Glib.c`/GOP display init.
    - `docs/02-kernel-boot-dtb-dtbo-cmdline.md` — `boot.img`/`recovery.img` parsing, gzip decompression, KASLR & physical load addresses, AArch64 kernel handoff registers, DTB/`dtbh`/`DtMatchVal` matching, RVA-by-RVA root-cause proof of the **`dtbo` brick**, and complete kernel `cmdline` reference.
    - `docs/03-odin-protocol-and-verified-boot.md` — `Odin.efi` lifecycle & USB transport (`0x04e8:0x685d`), `ODIN`/`LOKE` handshake & `0x64`–`0x69` wire protocol, sparse ext4 handling, `PitUpdate.c` 62-entry PIT-to-GPT mapping, Download Mode UI field sources (`DevAuth`, `btd`, `persistent`, `steady`, `bksecapp`), `Sec_Auth_*` / AVB 2.0, and `Sec_Emc`.
    - `docs/04-variant-comparison-F-vs-N-vs-A9200.md` — Cross-variant comparison of `F` vs `N` vs `A9200` (MBN `SW_ID` rev `7` vs `5`, `.data` UI JPEG array stride expansion in `N`, `A9200` FRP-binary & PIT lockout guards, `N` `GetPartitionSize` overflow helper, and carrier/region checks).
  - **Phase 2 — XBL (`xbl.elf`) & `bksecapp.mbn`**:
    - `docs/05-xbl-bds-reset-buttons-and-configs.md` — `xbl.elf` container, `Sec.te`, `apriori_order.json` (`64` drivers), embedded `.cfg` files, `QcomBds` launch of `LinuxLoader` from `ABOOT FV` (and retail shell/menu gating), `ResetRuntimeDxe` reboot reason codes (`0x00..0x49`) + EDL SCM `0x2000502`, and `ButtonsDxe` PMIC/GPIO key matrix (`KPDPWR`/`RESIN`/`VOL+`/`BIXBY`).
    - `docs/06-xbl-display-dxe-and-panel-handoff.md` — `DisplayDxe` AMOLED panel detection (`S6E3FA7_AMS628RF01` `1080x2220` & `AMS622MR01`), `kts1620`/LDO/GPIO power-up, DSI sequences, `DisplayPanelConfiguration` generation, and `DisplaySplashBufferInfo` (`0x9D400000` + `0x9F700000` DSI PLL codes) handoff.
    - `docs/07-xbl-samsung-dxe-muic-chg-vib-ldo.md` — Samsung's custom `Muic`, `Chg`, `Vib`, and `NpaLdo` DXE drivers: protocol vtables, SM5705 I2C/fuel-gauge/charger registers, `BATT_THERM` LUT, JIG resistor table, `S2DOS03` vibrator LDOs, and `NpaProtocol` test client.
    - `docs/08-xbl-loader-hwrev-and-bksecapp-tz.md` — `XBL_Loader`/`XBL_Ramdump` (`0x14015000`/`0x85e35000`), `hw_rev` via `kts1620_i2c` -> `SMEM 0x87`, LPDDR4 -> `SMEM 0x86`, EDL/IMEM cookies, `VerifiedBootDxe` & `TzDxe` SMCs, and 32-bit ARM `bksecapp.elf` (`APP_ID=0x888`) `0x138`-byte IPC command table (`0x0..0x66`) + QFPROM fuse addresses.
- `scripts/` — Reproducible unpacking and verification scripts (`unpack_abl.py`, `unpack_xbl_bksecapp.py`, `enrich_symbols.py`, `analyze_uefi_bootflow.py`, `analyze_dtb_cmdline.py`, `analyze_odin_protocol.py`, `diff_variants.py`, `analyze_xbl_bds_reset_keys.py`, `analyze_xbl_display.py`, `analyze_xbl_samsung_dxe.py`, `analyze_xbl_loader_bksecapp.py`).
- `extracted/` — Unpacked `abl.elf`, `xbl.elf`, `bksecapp.elf`, DXEs, `.cfg`s, `.bmp`s, and JSON/TSV metadata.
- `decomp/` — Headless Ghidra 12.1.4 UEFI-typed C decompilation (`all_decomp.c`, `functions.json`, `symbol_map.json`, `funcs/*.c`) for all 18 modules.
- `ghidra/` — Saved Ghidra `.gpr`/`.rep` databases, headless logs, and `scripts/ExportUefiAbl.java`.
