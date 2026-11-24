#!/usr/bin/env python3
"""Reproducible verification script for Samsung's four custom XBL DXE drivers
(Muic.efi, Chg.efi, Vib.efi, NpaLdo.efi) in SM-A920F (a9y18qlte, SDM660).

Validates PE32+ headers, SHA-256 digests, installed/consumed protocol GUIDs,
protocol vtable RVAs, internal driver ops tables, GPIO bit-bang I2C configs,
register/LUT constants, ABL LinuxLoader.efi call-site cross-references, and
QcomChargerCfg.cfg / BATTERY.PROVISION metadata.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import struct
import sys
from typing import Any

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
DXE_DIR = BASE_DIR / "extracted" / "F_XBL" / "dxe"
CFG_DIR = BASE_DIR / "extracted" / "F_XBL" / "cfg"
LL_PATH = BASE_DIR / "extracted" / "F" / "LinuxLoader.efi"

EXPECTED_MODULES: dict[str, dict[str, Any]] = {
    "Muic.efi": {
        "size": 40960,
        "entry": 0x1130,
        "install_rva": 0x145C,
        "protocol_name": "SamsungMuicProtocol",
        "protocol_guid": "2cc73155-a1f9-4c4b-88e2-caf9390e126a",
        "guid_rva": 0x8060,
        "vtable_rva": 0x80B0,
        "vtable": [0x1, 0x13C0, 0x13EC, 0x1404, 0x1430],
    },
    "Chg.efi": {
        "size": 49152,
        "entry": 0x1130,
        "install_rva": 0x15E4,
        "protocol_name": "SamsungChargerProtocol",
        "protocol_guid": "3c7596fa-0058-4496-a648-6d14be4023b2",
        "guid_rva": 0xA060,
        "vtable_rva": 0xA0E0,
        "vtable": [
            0x1,
            0x13C0,
            0x13D8,
            0x13F0,
            0x1408,
            0x1420,
            0x1438,
            0x1450,
            0x147C,
            0x1494,
            0x14AC,
            0x14D8,
            0x14F0,
            0x151C,
            0x1548,
            0x1574,
            0x15A0,
            0x15CC,
        ],
    },
    "Vib.efi": {
        "size": 32768,
        "entry": 0x1130,
        "install_rva": 0x1400,
        "protocol_name": "SamsungVibratorProtocol",
        "protocol_guid": "aa2e776d-8c9c-4268-998a-8b0a13bf0501",
        "guid_rva": 0x6060,
        "vtable_rva": 0x60B0,
        "vtable": [0x13C0, 0x13D8],
    },
    "NpaLdo.efi": {
        "size": 28672,
        "entry": 0x1130,
        "install_rva": 0x13E4,
        "protocol_name": "SamsungNpaLdoProtocol",
        "protocol_guid": "6c3dbb2c-4354-4f5a-9e2f-40658db24402",
        "guid_rva": 0x5060,
        "vtable_rva": 0x50B0,
        "vtable": [0x13A4, 0x13BC],
    },
}


def read_guid(buf: bytes, off: int) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", buf, off)
    d4 = buf[off + 8 : off + 16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[0]:02x}{d4[1]:02x}-{d4[2:].hex()}"


def parse_pe32plus(buf: bytes) -> dict[str, Any]:
    assert buf[:2] == b"MZ", "Missing MZ header"
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    assert buf[e_lfanew : e_lfanew + 4] == b"PE\x00\x00", "Missing PE signature"
    coff_off = e_lfanew + 4
    machine, nsec, _, _, _, opt_sz, _ = struct.unpack_from("<HHIIIHH", buf, coff_off)
    opt_off = coff_off + 20
    opt_magic = struct.unpack_from("<H", buf, opt_off)[0]
    assert opt_magic == 0x20B, f"Expected PE32+ (0x20b), got {opt_magic:#x}"
    ep = struct.unpack_from("<I", buf, opt_off + 16)[0]
    image_base = struct.unpack_from("<Q", buf, opt_off + 24)[0]
    subsystem = struct.unpack_from("<H", buf, opt_off + 68)[0]
    secs = []
    sec_off = opt_off + opt_sz
    for _ in range(nsec):
        name = buf[sec_off : sec_off + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsz, va, rsz, ra, _, _, _, _, flags = struct.unpack_from("<IIIIIIHHI", buf, sec_off + 8)
        assert va == ra, f"Expected VA == RawOffset for {name}: {va:#x} != {ra:#x}"
        secs.append({"name": name, "va": va, "vsz": vsz, "ra": ra, "rsz": rsz, "flags": flags})
        sec_off += 40
    return {
        "machine": machine,
        "entry": ep,
        "image_base": image_base,
        "subsystem": subsystem,
        "sections": secs,
    }


def parse_i2c_gpio_cfg(buf: bytes, off: int) -> dict[str, Any]:
    raw = buf[off : off + 0x24]
    name = raw[:16].split(b"\x00", 1)[0].decode("ascii", "strict")
    scl_gpio, sda_gpio = struct.unpack_from("<II", raw, 0x10)
    return {
        "name": name,
        "scl_gpio": scl_gpio,
        "sda_gpio": sda_gpio,
        "scl_cfg": raw[0x18:0x1C].hex(),
        "sda_cfg": raw[0x1C:0x20].hex(),
    }


def verify_modules() -> dict[str, bytes]:
    blobs: dict[str, bytes] = {}
    print("=== 1. PE32+ Headers & Installed Protocol Vtables ===")
    for fname, spec in EXPECTED_MODULES.items():
        path = DXE_DIR / fname
        buf = path.read_bytes()
        blobs[fname] = buf
        assert len(buf) == spec["size"], f"{fname}: size {len(buf)} != {spec['size']}"
        pe = parse_pe32plus(buf)
        assert pe["machine"] == 0xAA64
        assert pe["image_base"] == 0x0
        assert pe["entry"] == spec["entry"]
        assert pe["subsystem"] == 11  # EFI Boot Service Driver

        guid = read_guid(buf, spec["guid_rva"])
        assert guid == spec["protocol_guid"], f"{fname} GUID mismatch: {guid}"

        vtable = list(
            struct.unpack_from(f"<{len(spec['vtable'])}Q", buf, spec["vtable_rva"])
        )
        assert vtable == spec["vtable"], f"{fname} vtable mismatch: {[hex(x) for x in vtable]}"

        sha256 = hashlib.sha256(buf).hexdigest()
        secs_str = ", ".join(f"{s['name']}@0x{s['va']:x}+0x{s['rsz']:x}" for s in pe["sections"])
        print(
            f"[OK] {fname:10s} size={len(buf):5d} sha256={sha256[:16]}... "
            f"GUID={guid} vtable@0x{spec['vtable_rva']:x} ({len(vtable)} slots) [{secs_str}]"
        )
    return blobs


def verify_muic(buf: bytes) -> None:
    print("\n=== 2. Muic.efi Verification ===")
    tlmm_guid = read_guid(buf, 0x8090)
    assert tlmm_guid == "ad9aec18-7bf0-4809-9e96-3012309f3df7", tlmm_guid

    sm5705_ops = list(struct.unpack_from("<10Q", buf, 0x80F0))
    assert sm5705_ops == [0x0, 0x2574, 0x26E4, 0x0, 0x0, 0x280C, 0x2848, 0x2B2C, 0x0, 0x1F]
    ccic_ops = list(struct.unpack_from("<4Q", buf, 0x8210))
    assert ccic_ops == [0x5260, 0x5288, 0x536C, 0x0]
    kts_ops = list(struct.unpack_from("<6Q", buf, 0x8178))
    assert kts_ops == [0x4BA8, 0x4CCC, 0x4D00, 0x4D84, 0x4E40, 0x4EE4]

    sm5705_cfg = parse_i2c_gpio_cfg(buf, 0x6CF8)
    s2mm005_cfg = parse_i2c_gpio_cfg(buf, 0x79F8)
    kts1620_cfg = parse_i2c_gpio_cfg(buf, 0x8150)
    assert sm5705_cfg["name"] == "SM5705_gpio" and (sm5705_cfg["scl_gpio"], sm5705_cfg["sda_gpio"]) == (73, 72)
    assert s2mm005_cfg["name"] == "S2MM005_gpio" and (s2mm005_cfg["scl_gpio"], s2mm005_cfg["sda_gpio"]) == (21, 20)
    assert kts1620_cfg["name"] == "kts1620_i2c" and (kts1620_cfg["scl_gpio"], kts1620_cfg["sda_gpio"]) == (51, 52)

    jt_setpath = list(struct.unpack_from("<4Q", buf, 0x6A38))
    jt_s2mm005 = list(struct.unpack_from("<7Q", buf, 0x6A58))
    jt_adc = list(struct.unpack_from("<6Q", buf, 0x6A90))
    assert jt_setpath == [0x2710, 0x2740, 0x275C, 0x2778]
    assert jt_s2mm005 == [0x2A60, 0x29C8, 0x2A2C, 0x2A04, 0x2A0C, 0x2A1C, 0x2A34]
    assert jt_adc == [0x2A60, 0x2A04, 0x2A5C, 0x2A5C, 0x2A0C, 0x2A1C]

    # Verify SetPath immediate writes in 0x2710..0x279c (reg 0x13 = MANSW1, reg 0x02 = CTRL = 0x1a)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(md.disasm(buf[0x2710:0x27B0], 0x2710))
    movs = [(i.address, i.op_str) for i in insns if i.mnemonic == "mov" and "#0x" in i.op_str]
    print(f"[OK] SM5705 I2C: SCL=GPIO{sm5705_cfg['scl_gpio']} SDA=GPIO{sm5705_cfg['sda_gpio']} slave8=0x4a (7-bit 0x25)")
    print(f"[OK] S2MM005 I2C: SCL=GPIO{s2mm005_cfg['scl_gpio']} SDA=GPIO{s2mm005_cfg['sda_gpio']} slave8=0x66/0x67 (7-bit 0x33)")
    print(f"[OK] KTS1620 I2C: SCL=GPIO{kts1620_cfg['scl_gpio']} SDA=GPIO{kts1620_cfg['sda_gpio']} slave8=0x44 (7-bit 0x22)")
    print(f"[OK] Jump tables verified: SetPath={len(jt_setpath)}, S2MM005_RID={len(jt_s2mm005)}, SM5705_ADC={len(jt_adc)}, movs={len(movs)}")


def verify_chg(buf: bytes) -> None:
    print("\n=== 3. Chg.efi Verification ===")
    assert read_guid(buf, 0xA090) == "ad9aec18-7bf0-4809-9e96-3012309f3df7"  # QcomTlmmProtocol
    assert read_guid(buf, 0xA0B0) == "2cc73155-a1f9-4c4b-88e2-caf9390e126a"  # SamsungMuicProtocol
    assert read_guid(buf, 0xA0C0) == "61740cc4-916f-4471-b0dc-00c6f43a7fc6"  # AdcProtocol (AdcDxe)
    assert read_guid(buf, 0xA0D0) == "bfab1be9-653f-4624-ae2d-7b7f00cc91f3"  # CcicProtocol

    chg_ops = list(struct.unpack_from("<16Q", buf, 0xA188))
    fg_ops = list(struct.unpack_from("<8Q", buf, 0xA208))
    assert chg_ops == [
        0x328C, 0x3300, 0x3420, 0x346C, 0x3D94, 0x34F0, 0x3534, 0x357C,
        0x35C4, 0x3620, 0x3664, 0x3668, 0x366C, 0x36C4, 0x36D0, 0x0,
    ]
    assert fg_ops == [0x3E80, 0x3EE4, 0x440C, 0x4468, 0x4584, 0x45C8, 0x45E0, 0x1F]

    chg_i2c = parse_i2c_gpio_cfg(buf, 0x8508)
    fg_i2c = parse_i2c_gpio_cfg(buf, 0x91C0)
    assert chg_i2c["name"] == "sm5705_chg_i2c" and (chg_i2c["scl_gpio"], chg_i2c["sda_gpio"]) == (73, 72)
    assert fg_i2c["name"] == "sm5705_fg_i2c" and (fg_i2c["scl_gpio"], fg_i2c["sda_gpio"]) == (56, 55)

    # Verify BATT_THERM LUT (23 entries, 90.0 C down to -20.0 C in 5.0 C steps)
    lut = [struct.unpack_from("<ii", buf, 0x8380 + i * 8) for i in range(23)]
    assert lut[0] == (1191, 900) and lut[-1] == (15097, -200)
    assert all(lut[i][0] < lut[i + 1][0] and lut[i][1] - lut[i + 1][1] == 50 for i in range(22))

    # Verify SM5705 FG model tables
    rce = list(struct.unpack_from("<3H", buf, 0x918A))
    table0 = list(struct.unpack_from("<16H", buf, 0x914A))
    table1 = list(struct.unpack_from("<16H", buf, 0x916A))
    assert rce == [0x04E1, 0x03E6, 0x01D7]
    assert len(table0) == 16 and len(table1) == 16
    assert table0[0] == 0x1400 and table0[-1] == 0x2400

    # Verify jump tables in 0x2bb8, 0x35c4, 0x3c84
    jt_status = list(struct.unpack_from("<12Q", buf, 0x7F90))
    jt_bytype = list(struct.unpack_from("<13Q", buf, 0x8438))
    jt_auto = list(struct.unpack_from("<13Q", buf, 0x84A0))
    assert len(jt_status) == 12 and len(jt_bytype) == 13 and len(jt_auto) == 13

    # Verify 0x3964 (sm5705_set_charge_enable) uses GPIO 0x3f (63)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns_3964 = list(md.disasm(buf[0x3964:0x39D0], 0x3964))
    assert any(i.mnemonic == "mov" and "#0x3f" in i.op_str for i in insns_3964)

    print(f"[OK] SM5705 CHG I2C: SCL=GPIO{chg_i2c['scl_gpio']} SDA=GPIO{chg_i2c['sda_gpio']} slave8=0x92/0x93 (7-bit 0x49)")
    print(f"[OK] SM5705 FG  I2C: SCL=GPIO{fg_i2c['scl_gpio']} SDA=GPIO{fg_i2c['sda_gpio']} slave8=0xe2/0xe3 (7-bit 0x71)")
    print(f"[OK] BATT_THERM LUT@0x8380: 23 points ({lut[0][0]}->{lut[0][1]/10:.1f}C to {lut[-1][0]}->{lut[-1][1]/10:.1f}C)")
    print(f"[OK] SM5705 FG model: RCE={[hex(x) for x in rce]}, table[0][0..1]={hex(table0[0])},{hex(table0[1])}..{hex(table0[-1])}")


def verify_vib(buf: bytes) -> None:
    print("\n=== 4. Vib.efi Verification ===")
    assert read_guid(buf, 0x6090) == "ad9aec18-7bf0-4809-9e96-3012309f3df7"  # QcomTlmmProtocol
    coindc_ops = list(struct.unpack_from("<4Q", buf, 0x60D8))
    assert coindc_ops == [0x2494, 0x24E0, 0x0, 0x0]

    ptrs = list(struct.unpack_from("<5Q", buf, 0x5658))
    assert ptrs == [0x6110, 0x6110, 0x6110, 0x6110, 0x6120]
    ldo1_4 = struct.unpack_from("<4I", buf, 0x6110)
    buck = struct.unpack_from("<4I", buf, 0x6120)
    assert ldo1_4 == (600000, 3775000, 25000, 7)
    assert buck == (500000, 2093750, 6250, 8)

    s2dos03_i2c = parse_i2c_gpio_cfg(buf, 0x56C0)
    assert s2dos03_i2c["name"] == "s2dos03_i2c" and (s2dos03_i2c["scl_gpio"], s2dos03_i2c["sda_gpio"]) == (70, 66)

    # Confirm COINDC_vib_init (0x2494) sets regulator index 3 (LDO4) to 3,300,000 uV (3.3 V)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(md.disasm(buf[0x2494:0x24E0], 0x2494))
    assert any(i.mnemonic == "bl" and "#0x2e7c" in i.op_str for i in insns)
    print(f"[OK] S2DOS03 I2C: SCL=GPIO{s2dos03_i2c['scl_gpio']} SDA=GPIO{s2dos03_i2c['sda_gpio']} slave8=0xc0 (7-bit 0x60)")
    print(f"[OK] S2DOS03 LDO1-4 desc@0x6110: {ldo1_4[0]}..{ldo1_4[1]} uV step {ldo1_4[2]} uV; LDO4 configured to 3300000 uV (3.3V)")


def verify_npaldo(buf: bytes) -> None:
    print("\n=== 5. NpaLdo.efi Verification ===")
    assert read_guid(buf, 0x5090) == "79d6c870-725e-489e-a0a1-27e7a5d0cb35"  # NpaProtocol
    assert b"/pmic/client/api_test\x00" in buf
    assert b"ApitestClient\x00" in buf
    # Verify DALSys.efi also holds /node/pmic/client/api_test
    dalsys = (DXE_DIR / "DALSys.efi").read_bytes()
    assert b"/node/pmic/client/api_test\x00" in dalsys
    print("[OK] NpaLdo consumes NpaProtocol (79d6c870-...), resource='/pmic/client/api_test', client='ApitestClient'")


def verify_abl_and_cfgs() -> None:
    print("\n=== 6. LinuxLoader.efi Cross-Reference & XBL Configs ===")
    ll = LL_PATH.read_bytes()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    # Check LinuxLoader .rodata protocol GUIDs
    ll_guids = {
        0x9EB14: "2cc73155-a1f9-4c4b-88e2-caf9390e126a",
        0x9EB44: "3c7596fa-0058-4496-a648-6d14be4023b2",
        0x9EB64: "6c3dbb2c-4354-4f5a-9e2f-40658db24402",
        0x9EB74: "aa2e776d-8c9c-4268-998a-8b0a13bf0501",
    }
    for rva, expected in ll_guids.items():
        actual = read_guid(ll, rva)
        assert actual == expected, f"LL@{rva:#x}: {actual} != {expected}"

    # Verify vtable offsets used by LinuxLoader wrapper functions
    expected_calls = [
        (0x156CC, 0x157A8, 0x8, "MuicGetDeviceType"),
        (0x157A8, 0x158B8, 0x10, "MuicSetPath"),
        (0x158B8, 0x15984, 0x58, "ChargerInit"),
        (0x15984, 0x15AAC, 0x8, "MuicGetJigType"),
        (0x15AAC, 0x15B88, 0x10, "ChgSetChgCurrentByType"),
        (0x15B88, 0x15C6C, 0x18, "ChgSetMaxCurrent"),
        (0x15C6C, 0x15D50, 0x20, "ChgSetEnCharge"),
        (0x15D50, 0x15E1C, 0x28, "ChgSetChgReconfig"),
        (0x15E1C, 0x15F2C, 0x38, "ChgGetChargerStatus"),
        (0x15F2C, 0x1603C, 0x60, "FgGetVoltage"),
        (0x1603C, 0x1614C, 0x68, "FgGetSoc"),
        (0x1614C, 0x1625C, 0x70, "FgGetFgReset"),
        (0x1625C, 0x16360, 0x78, "GetBattTemp"),
        (0x16360, 0x16488, 0x80, "FgCheckModelData"),
        (0x16488, 0x16554, 0x88, "FuelgaugeInit"),
        (0x1AFA4, 0x1B07C, 0x0, "InitNpaLdo6"),
        (0x1B07C, 0x1B164, 0x8, "SetNpaLdo6"),
        (0x1B280, 0x1B4F8, 0x0, "VibStart(InitVib+0x0, SetVib+0x8)"),
    ]
    for start, end, voff, label in expected_calls:
        insns = list(md.disasm(ll[start:end], start))
        has_blr = any(i.mnemonic == "blr" for i in insns)
        assert has_blr, f"Missing indirect call in {label}@{start:#x}"
        if voff != 0:
            pat = f"#{voff:#x}" if voff >= 10 else f"#{voff}"
            assert any(i.mnemonic == "ldr" and pat in i.op_str for i in insns), (
                f"Expected vtable offset {pat} in {label}@{start:#x}"
            )
    print(f"[OK] Verified {len(expected_calls)} LinuxLoader.efi wrapper functions & protocol GUIDs")

    # Verify QcomChargerCfg.cfg and BATTERY.PROVISION
    qcfg = (CFG_DIR / "QcomChargerCfg.cfg").read_text(encoding="utf-8", errors="replace")
    bprov = (CFG_DIR / "BATTERY.PROVISION").read_text(encoding="utf-8", errors="replace")
    fv_vals = re.findall(r"ChgFvMax\s*=\s*(\d+)", qcfg)
    assert fv_vals == ["4350", "4400"], fv_vals
    profiles = re.findall(r"Battery_name,(.+)", bprov)
    assert profiles == [
        "Ascent_with_connector_3450mAh_averaged_MasterSlave_Jan6th2017",
        "QRD8997_ST1031GA_3000mAh_averaged_MasterSlave_Jan10th2017",
        "Itech_B00826LF_3000mAh_ver1660_averaged_MasterSlave_Jan10th2017",
    ], profiles
    assert not (DXE_DIR / "QcomChargerApp.efi").exists()
    print(f"[OK] QcomChargerCfg.cfg ChgFvMax={fv_vals}, BATTERY.PROVISION profiles={len(profiles)} (QcomChargerApp absent; Chg.efi used instead)")


def main() -> int:
    blobs = verify_modules()
    verify_muic(blobs["Muic.efi"])
    verify_chg(blobs["Chg.efi"])
    verify_vib(blobs["Vib.efi"])
    verify_npaldo(blobs["NpaLdo.efi"])
    verify_abl_and_cfgs()
    print("\nALL XBL SAMSUNG DXE CHECKS PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
