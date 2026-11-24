#!/usr/bin/env python3
"""Verification script for SM-A920F (a9y18qlte, SDM660) xbl.elf:
- ELF64 / MBN v5 / SignerVer02 / Outer FV / Sec.te / inner_dxe_fv / apriori_order
- Embedded UEFI configs (uefiplat.cfg, BDS_Menu.cfg, SecParti.cfg,
  QcomChargerCfg.cfg, tracer_event.cfg, BATTERY.PROVISION)
- QcomBds.efi boot targets, retail gating, and ABL handoff
- ResetRuntimeDxe.efi + PmicDxe.efi + LinuxLoader.efi reset reason pipeline
- ButtonsDxe.efi GPIO/PMIC matrix, keymap, ScanCode bits -> LinuxLoader/Odin
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import uuid
from collections import defaultdict
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parent.parent
XBL_DIR = BASE / "extracted" / "F_XBL"
CFG_DIR = XBL_DIR / "cfg"
DXE_DIR = XBL_DIR / "dxe"

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def read_u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def read_u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def read_u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def read_guid(buf: bytes, off: int) -> str:
    return str(uuid.UUID(bytes_le=buf[off : off + 16]))


def disasm_range(buf: bytes, start: int, end: int, base: int = 0) -> list[tuple[int, str, str]]:
    return [
        (ins.address, ins.mnemonic, ins.op_str)
        for ins in MD.disasm(buf[start:end], base + start)
    ]


def verify_xbl_container_and_sec_te() -> dict:
    xbl_path = XBL_DIR / "xbl.elf"
    xbl_bytes = xbl_path.read_bytes()
    meta = json.loads((XBL_DIR / "xbl_mbn_metadata.json").read_text())

    assert len(xbl_bytes) == meta["total_size"] == 2840100
    assert hashlib.sha256(xbl_bytes).hexdigest() == meta["total_sha256"]

    with xbl_path.open("rb") as f:
        elf = ELFFile(f)
        assert elf.elfclass == 64
        assert elf.header["e_machine"] == "EM_AARCH64"
        assert elf.header["e_entry"] == 0x14021C90
        assert elf.num_segments() == 16

        for seg_meta in meta["segments"]:
            idx = seg_meta["index"]
            seg = elf.get_segment(idx)
            off = seg["p_offset"]
            fsz = seg["p_filesz"]
            assert off == int(seg_meta["offset"], 16)
            assert fsz == int(seg_meta["filesz"], 16)
            assert seg["p_vaddr"] == int(seg_meta["vaddr"], 16)
            if fsz > 0:
                h = hashlib.sha256(xbl_bytes[off : off + fsz]).hexdigest()
                assert h == seg_meta["sha256"], f"seg {idx} sha mismatch"

    # MBN v5 header in Seg 1 (offset 0x1000)
    mbn = meta["mbn"]
    seg1_off = int(mbn["segment_offset"], 16)
    words = struct.unpack_from("<10I", xbl_bytes, seg1_off)
    assert words[0] == 5 and words[1] == 5
    assert words[4] == 0x1B00 and words[5] == 0x200 and words[7] == 0x100 and words[9] == 0x1800
    assert mbn["certs"][0]["subject"].startswith(
        "C = US, CN = SecTools Test User"
    )
    assert "01 0000000700000000 SW_ID" in mbn["certs"][0]["subject"]
    assert "03 0000000000000000 DEBUG" in mbn["certs"][0]["subject"]

    # SignerVer02 footer at 0x2b5424
    footer_off = int(meta["samsung_signer_footer"]["offset"], 16)
    assert footer_off == 0x2B5424
    assert xbl_bytes[footer_off : footer_off + 11] == b"SignerVer02"
    assert b"A920FXXS7CVH1" in xbl_bytes[footer_off:]

    # Seg 12 Outer FV (_FVH)
    seg12_off = int(meta["segments"][12]["offset"], 16)
    seg12_sz = int(meta["segments"][12]["filesz"], 16)
    assert seg12_off == 0x8D5A0 and seg12_sz == 0x1B5800
    assert xbl_bytes[seg12_off + 0x28 : seg12_off + 0x2C] == b"_FVH"

    # Sec.te ('VZ' TE header)
    sec_bytes = (XBL_DIR / "Sec.te").read_bytes()
    assert sec_bytes[:2] == b"VZ"
    machine = read_u16(sec_bytes, 2)
    num_sec = sec_bytes[4]
    subsys = sec_bytes[5]
    stripped = read_u16(sec_bytes, 6)
    entry_rva = read_u32(sec_bytes, 8)
    base_of_code = read_u32(sec_bytes, 12)
    image_base = read_u64(sec_bytes, 16)
    assert machine == 0xAA64
    assert num_sec == 3
    assert subsys == 11
    assert stripped == 0xF60
    assert entry_rva == 0x1000
    assert base_of_code == 0x1000
    assert image_base == 0x9FC01000

    sections = []
    for i in range(num_sec):
        off = 0x28 + i * 40
        sname = sec_bytes[off : off + 8].rstrip(b"\x00").decode("ascii")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<4I", sec_bytes, off + 8)
        sections.append((sname, vaddr, vsize, rptr, rsize))
    assert [s[0] for s in sections] == [".text", ".data", ".reloc"]
    assert sections[0] == (".text", 0x1000, 0x21000, 0x1000, 0x21000)
    assert sections[1] == (".data", 0x22000, 0x3000, 0x22000, 0x3000)
    assert sections[2] == (".reloc", 0x25000, 0x1000, 0x25000, 0x1000)

    loading_dxecore_off = sec_bytes.find(b"Loading DxeCore")
    assert loading_dxecore_off == 0x1BFF3
    assert image_base + loading_dxecore_off == 0x9FC1CFF3

    # Apriori order and DXE manifest
    apriori = json.loads((CFG_DIR / "apriori_order.json").read_text())
    manifest = json.loads((XBL_DIR / "dxe_manifest.json").read_text())
    assert len(apriori) == 82
    present_ap = [e for e in apriori if e["ui_name"] is not None]
    null_ap = [e for e in apriori if e["ui_name"] is None]
    assert len(present_ap) == 64
    assert len(null_ap) == 18
    assert len(manifest) == 82

    ui_to_idx = {e["ui_name"]: e["index"] for e in present_ap}
    for name in ("EnvDxe", "PmicDxe", "ResetRuntimeDxe", "ButtonsDxe", "QcomBds"):
        assert name in ui_to_idx, f"missing {name} in apriori"
    assert "QcomChargerApp" not in ui_to_idx
    assert "QcomChargerDxe" not in ui_to_idx

    return {
        "xbl_size": len(xbl_bytes),
        "apriori_total": len(apriori),
        "apriori_present": len(present_ap),
        "apriori_missing": len(null_ap),
        "key_apriori_indices": {
            n: ui_to_idx[n]
            for n in ("EnvDxe", "TzDxe", "PmicDxe", "ResetRuntimeDxe", "DisplayDxe", "ButtonsDxe", "QcomBds")
            if n in ui_to_idx
        },
    }


def verify_configs() -> dict:
    # 1. uefiplat.cfg
    uefiplat = (CFG_DIR / "uefiplat.cfg").read_text()
    assert "Version = 3" in uefiplat
    mem_entries = re.findall(r"^\s*0x[0-9A-Fa-f]+,\s*0x[0-9A-Fa-f]+,", uefiplat, re.M)
    # Count MemoryMap vs RegisterMap
    sec_mem = uefiplat.split("[MemoryMap]")[1].split("[RegisterMap]")[0]
    sec_reg = uefiplat.split("[RegisterMap]")[1].split("[ConfigParameters]")[0]
    sec_cfg = uefiplat.split("[ConfigParameters]")[1]
    mem_lines = [l for l in sec_mem.splitlines() if l.strip().startswith("0x")]
    reg_lines = [l for l in sec_reg.splitlines() if l.strip().startswith("0x")]
    assert len(mem_lines) == 14, f"MemoryMap len={len(mem_lines)}"
    assert len(reg_lines) == 33, f"RegisterMap len={len(reg_lines)}"

    expected_cfg = {
        "EnableShell": "0x1",
        "SharedIMEMBaseAddr": "0x146BF000",
        "DloadCookieAddr": "0x01FD3000",
        "DloadCookieValue": "0x10",
        "GCCResetValueAddress": "0x146BF028",
        "SecurityFlag": "0xC4",
        "DefaultChargerApp": '"QcomChargerApp"',
        "DefaultBDSBootApp": '"LinuxLoader"',
        "EnableLogFsSyncInRetail": "0x0",
    }
    for k, v in expected_cfg.items():
        m = re.search(rf"^\s*{k}\s*=\s*(.+?)\s*$", sec_cfg, re.M)
        assert m and m.group(1) == v, f"uefiplat {k}: got {m.group(1) if m else None}"

    # 2. BDS_Menu.cfg
    bds_menu = (CFG_DIR / "BDS_Menu.cfg").read_text()
    for token in (
        "Exit",
        "SecurityToggleApp",
        "DebugPolicyToggleApp",
        "RPMBProvision",
        "Shell",
        "BootUSBFirst",
        "Reboot",
        "edl",
        "UsbfnMsdApp",
        "Fastboot",
        "046fae99-cf2e-49ed-a6a8-a1488b7e80d3",
    ):
        assert token in bds_menu, f"BDS_Menu.cfg missing {token}"

    # 3. SecParti.cfg
    secparti = (CFG_DIR / "SecParti.cfg").read_text()
    assert "Version = 0x0100" in secparti
    assert "[RPMB.128KB]" in secparti and "[RPMB.256KB]" in secparti and "[GPT]" in secparti
    assert "8BF4B4F0 BAAE CF4E 9142 5DC30CDC3E77" in secparti
    assert "qcom.tz.uefisecapp" in secparti and "qcom.tz.winsecapp" in secparti

    # 4. QcomChargerCfg.cfg
    chg = (CFG_DIR / "QcomChargerCfg.cfg").read_text()
    assert "CfgVersion = 25" in chg
    assert "[PlatformCommon]" in chg and "[PlatformMTP]" in chg and "[PlatformQRD]" in chg
    assert "ChgFvMax  = 4350" in chg and "ChgFvMax  = 4400" in chg
    assert "ChgFccMax = 2000" in chg and "ChgFccMax = 3000" in chg

    # 5. tracer_event.cfg
    tracer = (CFG_DIR / "tracer_event.cfg").read_text()
    sw_events = re.findall(r'^([A-Z0-9_]+),"[^"]+",([01])\s*$', tracer, re.M)
    assert len(sw_events) == 9, f"tracer events count={len(sw_events)}"

    # 6. BATTERY.PROVISION
    batt = (CFG_DIR / "BATTERY.PROVISION").read_text()
    profiles = re.findall(r"^Battery_name,(.+)$", batt, re.M)
    batt_ids = re.findall(r"^Batt_id,(\d+)$", batt, re.M)
    checksums = re.findall(r"^Checksum,([0-9A-Fa-f]+)$", batt, re.M)
    assert len(profiles) == 3
    assert batt_ids == ["60000", "68000", "100000"]
    assert checksums == ["96AC", "D299", "FB8F"]

    return {
        "uefiplat_mem_regions": len(mem_lines),
        "uefiplat_reg_regions": len(reg_lines),
        "tracer_events": len(sw_events),
        "battery_profiles": profiles,
    }


def verify_qcom_bds() -> dict:
    qb = (DXE_DIR / "QcomBds.efi").read_bytes()
    # PE EntryPoint == 0x1130 -> branches to 0x103c -> calls 0x203c
    entry_dis = disasm_range(qb, 0x1130, 0x1160)
    assert entry_dis[-1][1] == "b" and entry_dis[-1][2] == "#0x103c"

    # BdsArchProtocol struct at 0x113a0 -> +0x00 = 0x1ce8 (BdsEntry)
    assert read_u64(qb, 0x113A0) == 0x1CE8
    assert read_guid(qb, 0x111A0) == "665e3ff6-46cc-11d4-9a38-0090273fc14d"  # gEfiBdsArchProtocolGuid
    assert read_guid(qb, 0x11160) == "046fae99-cf2e-49ed-a6a8-a1488b7e80d3"  # ABL / ABOOT FV GUID
    assert read_guid(qb, 0x11060) == "882f8c2b-9646-435f-8de5-f208ff80c1bd"  # QcomTokenSpaceGuid
    assert read_guid(qb, 0x11050) == "bedaeabc-5e70-4d66-9733-213d072b9d04"  # UefiCfgLib GUID
    assert read_guid(qb, 0x11030) == "77fa9abd-0359-4d32-bd60-28f4e78f784b"  # AttemptUSBFirst var GUID

    # FUN_0000c84c unconditionally returns EFI_UNSUPPORTED (0x8000000000000003)
    c84c_dis = disasm_range(qb, 0xC84C, 0xC854)
    assert c84c_dis == [
        (0xC84C, "mov", "x0, #-0x7ffffffffffffffd"),
        (0xC850, "ret", ""),
    ], f"unexpected c84c: {c84c_dis}"

    # Retail QcomBds strings: has DefaultBDSBootApp / logfs / BootNext / BootOrder, NO BDS_Menu.cfg / QcomChargerApp
    for s in ("DefaultBDSBootApp", "UEFI Total : %d ms", "EnableLogFsSyncInRetail", "SharedIMEMBaseAddr", "BootNext", "BootOrder"):
        assert s.encode("ascii") in qb, f"QcomBds missing ASCII {s}"
    for ws in ("AttemptUSBFirst", "BootNext", "BootOrder", "logfs", "efiesp", "FwVerStr"):
        assert ws.encode("utf-16le") in qb, f"QcomBds missing UTF-16LE {ws}"
    for absent in ("BDS_Menu.cfg", "QcomChargerApp", "EnableShell"):
        assert absent.encode("ascii") not in qb, f"QcomBds unexpectedly contains ASCII {absent}"
        assert absent.encode("utf-16le") not in qb, f"QcomBds unexpectedly contains UTF-16LE {absent}"

    return {"bds_entry_rva": "0x1ce8", "aboot_fv_guid": "046fae99-cf2e-49ed-a6a8-a1488b7e80d3"}


def verify_reset_and_linuxloader() -> dict:
    rr = (DXE_DIR / "ResetRuntimeDxe.efi").read_bytes()
    pmic = (DXE_DIR / "PmicDxe.efi").read_bytes()
    ll = (BASE / "extracted" / "F" / "LinuxLoader.efi").read_bytes()

    # GUIDs & protocol struct
    assert read_guid(rr, 0x90B0) == "27cfac88-46cc-11d4-9a38-0090273fc14d"  # EfiResetArchProtocolGuid
    assert read_guid(rr, 0x90C0) == "a022155a-4828-4535-a499-11f15240b91b"  # QcomResetReasonProtocol
    assert read_guid(rr, 0x9120) == "9ba45b66-efa4-441c-a3e4-ed2224786be2"  # PmicPonProtocol

    rr_vt = struct.unpack_from("<4Q", rr, 0x9130)
    assert rr_vt == (0x10002, 0x1704, 0x1714, 0x10000), f"rr_vt={[hex(x) for x in rr_vt]}"

    # Thunks at 0x1704 -> 0x3074 and 0x1714 -> 0x31b4
    assert disasm_range(rr, 0x1704, 0x1718) == [
        (0x1704, "mov", "x0, x1"),
        (0x1708, "mov", "x1, x2"),
        (0x170C, "mov", "x2, x3"),
        (0x1710, "b", "#0x3074"),
        (0x1714, "b", "#0x31b4"),
    ]

    # Strings in ResetRuntimeDxe
    assert rr[0x79FA:0x7A02] == b"E\x00D\x00L\x00\x00\x00"
    assert rr[0x7A02:0x7A1A] == b"R\x00E\x00S\x00E\x00T\x00_\x00P\x00A\x00R\x00A\x00M\x00\x00\x00"
    assert rr[0x7A1A:0x7A2A] == b"U\x00N\x00K\x00N\x00O\x00W\x00N\x00\x00\x00"

    # GetResetReason (0x3074) calls [x9, #0x20] with w1=3 (XVDD_RB_SPARE) and lsr #1
    d3074 = disasm_range(rr, 0x30D8, 0x3154)
    assert any(m == "ldr" and "[x9, #0x20]" in op for _, m, op in d3074)
    assert any(m == "mov" and op == "w1, #3" for _, m, op in d3074)
    assert any(m == "lsr" and "#1" in op for _, m, op in d3074)

    # SetResetReason helper (0x349c) calls [x9, #0x28] with w1=3, w3=0xfe, lsl w2, w19, #1
    d349c = disasm_range(rr, 0x34DC, 0x3500)
    assert any(m == "ldr" and "[x9, #0x28]" in op for _, m, op in d349c)
    assert any(m == "mov" and op == "w1, #3" for _, m, op in d349c)
    assert any(m == "mov" and op == "w3, #0xfe" for _, m, op in d349c)
    assert any(m == "lsl" and op == "w2, w19, #1" for _, m, op in d349c)

    # PmicDxe vtable 0x2f638 (paired with 9ba45b66) -> GetSpareReg (+0x20=0x3174->0xfe0c) / SetSpareReg (+0x28=0x31a4->0xfe74)
    assert read_u64(pmic, 0x2F638) == 0x10009
    assert read_u64(pmic, 0x2F658) == 0x3174
    assert read_u64(pmic, 0x2F660) == 0x31A4
    assert any(m == "add" and "#0x88c" in op for _, m, op in disasm_range(pmic, 0xFE58, 0xFE74))
    assert any(m == "add" and "#0x88c" in op for _, m, op in disasm_range(pmic, 0xFEC0, 0xFEE4))

    # LinuxLoader.efi 0x12b9c jump table at 0x7a188 (0x00..0x49 = 74 entries)
    jt = struct.unpack_from("<74Q", ll, 0x7A188)
    by_tgt = defaultdict(list)
    for code, tgt in enumerate(jt):
        by_tgt[tgt].append(code)
    non_default = sorted(c for tgt, codes in by_tgt.items() if tgt != 0x12DDC for c in codes)
    assert non_default == [
        0x00, 0x01, 0x02, 0x03, 0x14, 0x15, 0x1A,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2C,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x3E, 0x3F, 0x48, 0x49,
    ], f"unexpected cases: {[hex(c) for c in non_default]}"

    return {
        "pmic_xvdd_rb_spare_reg": hex(0x88C + 3),
        "linuxloader_non_default_cases": len(non_default),
    }


def verify_buttons_and_keys() -> dict:
    btn = (DXE_DIR / "ButtonsDxe.efi").read_bytes()
    ll = (BASE / "extracted" / "F" / "LinuxLoader.efi").read_bytes()
    odin = (BASE / "extracted" / "F" / "Odin.efi").read_bytes()

    # Protocol vtables & DevicePath
    assert struct.unpack_from("<3Q", btn, 0x7130) == (0x1438, 0x1450, 0x0)
    assert struct.unpack_from("<6Q", btn, 0x7148) == (0x1524, 0x153C, 0x0, 0x168C, 0x1694, 0x1838)
    assert struct.unpack_from("<5I", btn, 0x71B8) == (1, 2, 3, 9, 0)
    assert read_guid(btn, 0x7090) == "97044b58-fea4-4ad0-9d0b-e417d60f11a1"
    assert read_guid(btn, 0x7100) == "9ba45b66-efa4-441c-a3e4-ed2224786be2"

    # Keymap & GPIO config in ButtonsDxe: EnableInput(1, 7) -> VOL+, EnableInput(1, 8) -> BIXBY
    d3cac = disasm_range(btn, 0x3CAC, 0x3D28)
    assert any(m == "mov" and op == "w1, #7" for _, m, op in d3cac)
    assert any(m == "mov" and op == "w1, #8" for _, m, op in d3cac)

    # ConvertEfiKeyCode (0x39ac) ScanCode bit assignments for KeyIDs {2->0x01, 3->0x02, 7->0x40, 1->0x80, 9->0x20}
    d39ac = disasm_range(btn, 0x39AC, 0x3AF0)
    mov_ops = [(a, op) for a, m, op in d39ac if m == "mov"]
    for bit_imm in ("#0x80", "#0x40", "#0x20", "#1", "#2"):
        assert any(op.endswith(", " + bit_imm) for _, op in mov_ops), f"missing {bit_imm} in ConvertEfiKeyCode"

    # Verify LinuxLoader key checks in 0x12e10 (Recovery 0x21/0x81/0xa1, Download 0x02/0x22/0x82/0xa2)
    d12e10 = disasm_range(ll, 0x12E10, 0x12F80)
    cmp_vals = {op.split("#")[-1] for _, m, op in d12e10 if m in ("cmp", "mov") and "#" in op}
    for k in ("0x21", "0x81", "0xa1", "2", "0x22", "0x82", "0xa2"):
        assert k in cmp_vals, f"LinuxLoader 0x12e10 missing {k} (got {cmp_vals})"

    # Verify Odin.efi 0xfed4 (0x80 Power) and 0xfff4 (0x01 / 0x02 Vol+/Vol-)
    dfed4 = disasm_range(odin, 0xFED4, 0xFF80)
    assert any(m == "cmp" and "#0x80" in op for _, m, op in dfed4)
    dfff4 = disasm_range(odin, 0xFFF4, 0x10080)
    assert any(m == "cmp" and "#1" in op for _, m, op in dfff4)
    assert any(m == "cmp" and "#2" in op for _, m, op in dfff4)

    return {
        "keymap": [1, 2, 3, 9, 0],
        "pmic_gpios": {"VOL+": "PMIC1 GPIO6 (arg 7)", "BIXBY": "PMIC1 GPIO7 (arg 8)"},
    }


def main() -> None:
    res = {
        "xbl_container": verify_xbl_container_and_sec_te(),
        "configs": verify_configs(),
        "qcom_bds": verify_qcom_bds(),
        "reset_runtime": verify_reset_and_linuxloader(),
        "buttons_dxe": verify_buttons_and_keys(),
    }
    print(json.dumps(res, indent=2))
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
