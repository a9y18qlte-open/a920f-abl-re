#!/usr/bin/env python3
"""Verify XBL_Loader / XBL_Ramdump (xbl_loader.elf), VerifiedBootDxe.efi,
TzDxe.efi, and Samsung's 32-bit ARM TrustZone applet bksecapp.elf.

Strictly read-only against extracted/ and decomp/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile

BASE_DIR = Path(__file__).resolve().parent.parent

XBL_ELF_PATH = BASE_DIR / "extracted/F_XBL/xbl_loader.elf"
XBL_META_PATH = BASE_DIR / "extracted/F_XBL/xbl_mbn_metadata.json"
UEFIPLAT_CFG_PATH = BASE_DIR / "extracted/F_XBL/cfg/uefiplat.cfg"
VBDXE_PATH = BASE_DIR / "extracted/F_XBL/dxe/VerifiedBootDxe.efi"
TZDXE_PATH = BASE_DIR / "extracted/F_XBL/dxe/TzDxe.efi"
BK_ELF_PATH = BASE_DIR / "extracted/F_BKSECAPP/bksecapp.elf"
BK_META_PATH = BASE_DIR / "extracted/F_BKSECAPP/bksecapp_mbn_metadata.json"

GUIDS_EXPECTED = {
    "QcomVerifiedBootProtocol": "8e5eff91-21b6-47d3-af2b-c15a01e020ec",
    "QcomTokenSpaceGuid": "882f8c2b-9646-435f-8de5-f208ff80c1bd",
    "QcomScmProtocol": "77ed108d-8524-4b8b-9d2e-34987aecb9c1",
    "QcomQseecomProtocol": "a74862ce-680f-4fe1-a311-df41f4030391",
    "EfiHash2Protocol_Qcom": "55b1d734-c5e1-49db-9647-b16afb0e305b",
    "EfiHashAlgorithmSha256Guid": "51aa59de-fdf2-4ea3-bc63-875fb7842ee9",
}

EXPECTED_OEM_PK_HASH = [
    (0x7801C8, 0x5D9AC35C, 0xF5F4E12E),
    (0x7801D0, 0x3911E7F6, 0x9D50A2AD),
    (0x7801D8, 0x250C686B, 0x01131933),
    (0x7801E0, 0x9790ED40, 0xC39F9FBC),
]

EXPECTED_DDR_VENDORS = {
    1: "Samsung",
    5: "Nanya",
    6: "SK hynix",
    8: "Winbond",
    9: "ESMT",
}

EXPECTED_SBL1_CONFIG_NAMES = [
    (0x16, "PMIC Image Loaded, Delta"),
    (0x200, "APDP Image Loaded, Delta"),
    (0x5, "QSEE Dev Config Image Loaded, Delta"),
    (0x7, "QSEE Image Loaded, Delta"),
    (0x15, "QHEE Image Loaded, Delta"),
    (0xA, "RPM Image Loaded, Delta"),
    (0x11, "STI Image Loaded, Delta"),
    (0x1C, "ABL Image Loaded, Delta"),
    (0x9, "APPSBL Image Loaded, Delta"),
]


class ElfMapper:
    """Maps ELF virtual addresses to file offsets for loaded segments."""

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.segs: list[tuple[int, int, int]] = []
        import io

        elf = ELFFile(io.BytesIO(raw))
        self.entry = elf.header["e_entry"]
        self.ei_class = str(elf.header["e_ident"]["EI_CLASS"])
        self.machine = str(elf.header["e_machine"])
        self.phnum = elf.header["e_phnum"]
        self.segments_info = []
        for idx, seg in enumerate(elf.iter_segments()):
            h = seg.header
            self.segments_info.append({
                "index": idx,
                "type": str(h.p_type),
                "offset": hex(h.p_offset),
                "vaddr": hex(h.p_vaddr),
                "paddr": hex(h.p_paddr),
                "filesz": hex(h.p_filesz),
                "memsz": hex(h.p_memsz),
                "flags": hex(h.p_flags),
            })
            if h.p_type == "PT_LOAD" and h.p_filesz > 0:
                self.segs.append((h.p_vaddr, h.p_offset, h.p_filesz))

    def va_to_off(self, va: int) -> int:
        for vaddr, off, filesz in self.segs:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        raise KeyError(f"VA {va:#x} not in any file-backed PT_LOAD segment")

    def read(self, va: int, size: int) -> bytes:
        off = self.va_to_off(va)
        return self.raw[off : off + size]

    def read_u32(self, va: int) -> int:
        return struct.unpack_from("<I", self.raw, self.va_to_off(va))[0]

    def read_u64(self, va: int) -> int:
        return struct.unpack_from("<Q", self.raw, self.va_to_off(va))[0]

    def read_cstr(self, va: int) -> str:
        off = self.va_to_off(va)
        end = self.raw.find(b"\x00", off)
        if end < 0:
            raise ValueError(f"Unterminated string at {va:#x}")
        return self.raw[off:end].decode("ascii", errors="strict")


def decode_guid(blob: bytes, offset: int) -> str:
    return str(uuid.UUID(bytes_le=blob[offset : offset + 16]))


def parse_pe_info(blob: bytes) -> dict[str, Any]:
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    machine, nsec = struct.unpack_from("<HH", blob, e_lfanew + 4)
    opt_sz = struct.unpack_from("<H", blob, e_lfanew + 20)[0]
    ep_rva = struct.unpack_from("<I", blob, e_lfanew + 24 + 16)[0]
    imgbase = struct.unpack_from("<Q", blob, e_lfanew + 24 + 24)[0]
    assert machine == 0xAA64, f"Expected AArch64 PE32+, got {machine:#x}"
    assert imgbase == 0, f"Expected ImageBase=0, got {imgbase:#x}"
    sec_tbl = e_lfanew + 24 + opt_sz
    sections = []
    for i in range(nsec):
        name, vsz, va, rsz, roff = struct.unpack_from("<8sIIII", blob, sec_tbl + i * 40)
        sections.append({
            "name": name.rstrip(b"\x00").decode("ascii", "replace"),
            "vaddr": hex(va),
            "vsize": hex(vsz),
            "raw_off": hex(roff),
            "raw_size": hex(rsz),
        })
    return {
        "machine": hex(machine),
        "image_base": hex(imgbase),
        "entry_point_rva": hex(ep_rva),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "sections": sections,
    }


def verify_xbl_loader() -> dict[str, Any]:
    raw = XBL_ELF_PATH.read_bytes()
    meta = json.loads(XBL_META_PATH.read_text())
    mapper = ElfMapper(raw)

    assert mapper.ei_class == "ELFCLASS64"
    assert mapper.machine == "EM_AARCH64"
    assert mapper.entry == 0x14021C90
    assert mapper.phnum == 16
    # Verify patched Segment 12 (0x9fc00000 UEFI FD) is PT_NULL in xbl_loader.elf
    assert mapper.segments_info[12]["type"] == "PT_NULL"
    assert mapper.segments_info[12]["vaddr"] == "0x9fc00000"
    assert meta["segments"][12]["type"] == "PT_LOAD"
    assert meta["samsung_signer_footer"]["build_id"] == "A920FXXS7CVH1"

    # Verify key init table pointers around 0x1407a610..0x1407a760
    init_ptrs = [mapper.read_u64(0x1407A6B0 + i * 8) for i in range(22)]
    assert init_ptrs[2] == 0x14024694, f"Expected boot_dload_check at +0x10: {init_ptrs[2]:#x}"
    assert init_ptrs[3] == 0x140362B8, f"Expected boot_smem_init at +0x18: {init_ptrs[3]:#x}"
    assert init_ptrs[4] == 0x140258A4, f"Expected hw_rev/ddr SMEM writer at +0x20: {init_ptrs[4]:#x}"
    assert init_ptrs[5] == 0x1402403C, f"Expected boot_dload_smem at +0x28: {init_ptrs[5]:#x}"
    assert init_ptrs[11] == 0x140366DC, f"Expected boot_ram_partition at +0x58: {init_ptrs[11]:#x}"

    # Verify kts1620_i2c vtable at 0x1407aff0
    kts_vtable = [mapper.read_u64(0x1407AFF0 + i * 8) for i in range(6)]
    assert kts_vtable == [
        0x14025A58,
        0x14025B5C,
        0x14025B80,
        0x14025BE4,
        0x14025C7C,
        0x14025CFC,
    ], f"Unexpected kts1620 vtable: {[hex(x) for x in kts_vtable]}"
    assert mapper.read_cstr(0x1407AFC8) == "kts1620_i2c"

    # Verify DDR vendor table at 0x1407b588
    ddr_vendors = {}
    for idx, expected in EXPECTED_DDR_VENDORS.items():
        ptr = mapper.read_u64(0x1407B588 + idx * 8)
        name = mapper.read_cstr(ptr)
        assert name == expected, f"DDR vendor[{idx}] mismatch: {name!r} != {expected!r}"
        ddr_vendors[idx] = name

    # Verify sbl1_config_table at 0x1407a768 (9 entries, stride 0x90)
    sbl1_cfg = []
    for i in range(9):
        base = 0x1407A768 + i * 0x90
        host_id = mapper.read_u32(base)
        img_type = mapper.read_u32(base + 0x10)
        exec_fn = mapper.read_u64(base + 0x30)
        pre_fn = mapper.read_u64(base + 0x40)
        post_fn = mapper.read_u64(base + 0x48)
        part_guid = decode_guid(raw, mapper.va_to_off(mapper.read_u64(base + 0x50)))
        log_str = mapper.read_cstr(mapper.read_u64(base + 0x58))
        exp_type, exp_str = EXPECTED_SBL1_CONFIG_NAMES[i]
        assert host_id == 0x15
        assert img_type == exp_type, f"Entry {i} img_type {img_type:#x} != {exp_type:#x}"
        assert log_str == exp_str, f"Entry {i} log_str {log_str!r} != {exp_str!r}"
        sbl1_cfg.append({
            "index": i,
            "image_type": hex(img_type),
            "partition_guid": part_guid,
            "exec_fn": hex(exec_fn) if exec_fn else None,
            "pre_fn": hex(pre_fn) if pre_fn else None,
            "post_fn": hex(post_fn) if post_fn else None,
            "log_str": log_str,
        })

    # Verify reset reason 3-byte strings at 0x1407aea4
    rr_codes = [mapper.raw[mapper.va_to_off(0x1407AEA4) + i * 3 : mapper.va_to_off(0x1407AEA4) + i * 3 + 2].decode("ascii", "replace") for i in range(1, 12)]
    assert rr_codes == ["SP", "WP", "DP", "KP", "MP", "PP", "RP", "BP", "NP", "TP", "NP"]

    # Verify key strings inside XBL_Loader / XBL_Ramdump
    for needle in [
        b"DDR vendor:%s@%p",
        b"HW REV:%d",
        b"@ Enter EDL MODE by volumn key at USER BINARY !!",
        b"TCSR reg value 0x%x ",
        b"Target was saved rr_data, Maybe entered upload before",
        b"[ UPLOAD MODE ]",
        b"FORCE UPLOAD is enabled!",
        b"A9Y18QLTE_EUR_OPEN",
        b"A920FXXS7CVH1",
    ]:
        assert needle in raw, f"Missing expected string in xbl_loader.elf: {needle!r}"

    # Verify uefiplat.cfg cookies match
    cfg_txt = UEFIPLAT_CFG_PATH.read_text()
    for token in [
        "SharedIMEMBaseAddr    = 0x146BF000",
        "DloadCookieAddr = 0x01FD3000",
        "DloadCookieValue = 0x10",
        "GCCResetValueAddress = 0x146BF028",
        "DBIDumpDDRBase = 0x9FFD0000",
    ]:
        assert token in cfg_txt, f"Missing uefiplat.cfg setting: {token}"

    return {
        "entry": hex(mapper.entry),
        "segments_count": mapper.phnum,
        "ddr_vendors": ddr_vendors,
        "kts1620_vtable": [hex(x) for x in kts_vtable],
        "sbl1_config_table": sbl1_cfg,
        "reset_reason_codes": rr_codes,
    }


def verify_verified_boot_dxe() -> dict[str, Any]:
    vb = VBDXE_PATH.read_bytes()
    pe = parse_pe_info(vb)

    guids = {
        "EfiHashAlgorithmSha256Guid": decode_guid(vb, 0xC020),
        "QcomTokenSpaceGuid": decode_guid(vb, 0xC050),
        "EfiHash2Protocol_Qcom": decode_guid(vb, 0xC0B0),
        "QcomVerifiedBootProtocol": decode_guid(vb, 0xC0C0),
        "QcomScmProtocol": decode_guid(vb, 0xC0F0),
        "QcomQseecomProtocol": decode_guid(vb, 0xC100),
    }
    for k, g in guids.items():
        if k in GUIDS_EXPECTED:
            assert g == GUIDS_EXPECTED[k], f"{k} GUID mismatch: {g} != {GUIDS_EXPECTED[k]}"

    vtable = [struct.unpack_from("<Q", vb, 0xC188 + i * 8)[0] for i in range(10)]
    assert vtable[0] == 0x10002, f"Unexpected QcomVerifiedBootProtocol rev: {vtable[0]:#x}"
    expected_methods = [0x155C, 0x1494, 0x1F98, 0x1A64, 0x24A0, 0x1C3C, 0x23FC, 0x2730, 0x2798]
    assert vtable[1:] == expected_methods, f"VB vtable mismatch: {[hex(x) for x in vtable[1:]]}"

    # Verify SCM IDs in VerifiedBootDxe.efi via Capstone at 0x3858, 0x39ec, 0x3ae8
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    smc_constants = set()
    for va_start, size in [(0x3858, 0xD4), (0x39EC, 0xC8), (0x3AE8, 0x100)]:
        insns = list(md.disasm(vb[va_start : va_start + size], va_start))
        for i in range(len(insns) - 1):
            if insns[i].mnemonic == "mov" and insns[i + 1].mnemonic == "movk":
                hi = int(insns[i].op_str.split("#")[-1], 16)
                lo = int(insns[i + 1].op_str.split("#")[-1].split(",")[0], 16)
                smc_constants.add(hi | lo)
    for expected_smc in (0x2000604, 0x2000801, 0x2000603):
        assert expected_smc in smc_constants, f"Missing SMC ID {expected_smc:#x} in VerifiedBootDxe"

    return {
        "pe": pe,
        "guids": guids,
        "vb_protocol_revision": hex(vtable[0]),
        "vb_protocol_methods": [hex(x) for x in vtable[1:]],
        "smc_ids_verified": sorted(hex(x) for x in smc_constants),
    }


def verify_tz_dxe() -> dict[str, Any]:
    tz = TZDXE_PATH.read_bytes()
    pe = parse_pe_info(tz)

    guids = {
        "QcomScmProtocol": decode_guid(tz, 0xF120),
        "QcomQseecomProtocol": decode_guid(tz, 0xF160),
    }
    for k, g in guids.items():
        assert g == GUIDS_EXPECTED[k], f"{k} GUID mismatch: {g} != {GUIDS_EXPECTED[k]}"

    qseecom_vtable = [struct.unpack_from("<Q", tz, 0xF248 + i * 8)[0] for i in range(8)]
    assert qseecom_vtable[0] == 0x10006
    assert qseecom_vtable[1:] == [0x2708, 0x265C, 0x25B4, 0x2D84, 0x4260, 0x288C, 0x2D94]

    scm_vtable = [struct.unpack_from("<Q", tz, 0xF338 + i * 8)[0] for i in range(8)]
    assert scm_vtable[0] == 0x10001
    assert scm_vtable[1:] == [0x4E74, 0x4E7C, 0x4E84, 0x5238, 0x4E8C, 0x5310, 0x4D28]

    # Count actual `smc #0` instructions in .text (0x5480..0x5660)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    smc_sites = []
    for insn in md.disasm(tz[0x5480:0x5660], 0x5480):
        if insn.mnemonic == "smc":
            smc_sites.append(hex(insn.address))
    assert smc_sites == [
        "0x54fc",
        "0x5530",
        "0x555c",
        "0x557c",
        "0x559c",
        "0x55c0",
        "0x55e4",
        "0x562c",
    ], f"Unexpected smc #0 sites in 0x5480..0x5660: {smc_sites}"

    return {
        "pe": pe,
        "guids": guids,
        "qseecom_protocol_revision": hex(qseecom_vtable[0]),
        "qseecom_protocol_methods": [hex(x) for x in qseecom_vtable[1:]],
        "scm_protocol_revision": hex(scm_vtable[0]),
        "scm_protocol_methods": [hex(x) for x in scm_vtable[1:]],
        "smc_instruction_rvas": smc_sites,
    }


def verify_bksecapp() -> dict[str, Any]:
    raw = BK_ELF_PATH.read_bytes()
    meta = json.loads(BK_META_PATH.read_text())
    mapper = ElfMapper(raw)

    assert mapper.ei_class == "ELFCLASS32"
    assert mapper.machine == "EM_ARM"
    assert mapper.entry == 0x0
    assert mapper.phnum == 8
    assert meta["samsung_signer_footer"]["build_id"] == "A920FXXS7CVH1"
    assert "APP_ID" in meta["mbn"]["certs"][0]["subject"]
    assert "0000000000000888 APP_ID" in meta["mbn"]["certs"][0]["subject"]

    # Check GOT pointers in PT_LOAD seg 4 (0x4e000 -> file off 0x38f00)
    got_canary = mapper.read_u32(0x4E00C)
    got_pk_table = mapper.read_u32(0x4E010)
    got_tima_pub = mapper.read_u32(0x4E014)
    assert got_pk_table == 0x1B020, f"Unexpected PK table VA: {got_pk_table:#x}"

    # Verify OEM PK Hash fuse table at 0x1b020
    pk_rows = []
    for i, (exp_addr, exp_lo, exp_hi) in enumerate(EXPECTED_OEM_PK_HASH):
        addr = mapper.read_u32(got_pk_table + i * 12)
        lo = mapper.read_u32(got_pk_table + i * 12 + 4)
        hi = mapper.read_u32(got_pk_table + i * 12 + 8)
        assert (addr, lo, hi) == (exp_addr, exp_lo, exp_hi), (
            f"OEM_PK_HASH[{i}] mismatch: {(hex(addr), hex(lo), hex(hi))}"
        )
        pk_rows.append({"fuse_addr": hex(addr), "lsb": hex(lo), "msb": hex(hi)})

    # Verify Thumb-2 QFPROM fuse addresses referenced in handlers
    md_thm = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    fuse_refs = {}
    handler_vas = {
        "cmd_0x0_wb_read": (0x8F0, 0x92),
        "cmd_0x1_wb_blow": (0x860, 0x7C),
        "cmd_0x7_rp_en": (0xC60, 0x8C),
        "cmd_0x8_rp_ignore": (0xD04, 0x98),
        "cmd_0xb_secboot_p1": (0x4B8, 0x86),
        "cmd_0xb_secboot_p2": (0x554, 0x96),
        "cmd_0xb_secboot_p3": (0x600, 0x86),
        "cmd_0xd_rp_xbl": (0xDB0, 0xA6),
        "cmd_0xe_rp_pil": (0xE6C, 0xFE),
        "cmd_0xf_rp_rpm": (0x1030, 0x96),
        "cmd_0x10_rp_tz": (0xF84, 0x96),
        "cmd_0x11_rp_hyp": (0x10DC, 0x96),
        "cmd_0x12_rp_dp": (0x1188, 0x96),
        "cmd_0x13_rp_devcfg": (0x1234, 0x96),
        "cmd_0x15_rpmb_fuse": (0x12E0, 0x78),
        "cmd_0x18_ek_read": (0x162C, 0x82),
        "cmd_0x19_1b_ek_write": (0x157C, 0x98),
    }
    for name, (va, sz) in handler_vas.items():
        insns = list(md_thm.disasm(mapper.read(va, sz), va))
        movw_vals: dict[str, int] = {}
        found = []
        for insn in insns:
            if insn.mnemonic == "movw":
                reg, imm = insn.op_str.split(",")
                movw_vals[reg.strip()] = int(imm.strip().lstrip("#"), 16)
            elif insn.mnemonic == "movt":
                reg, imm = insn.op_str.split(",")
                reg = reg.strip()
                hi = int(imm.strip().lstrip("#"), 16)
                if reg in movw_vals:
                    val = (hi << 16) | movw_vals[reg]
                    if (val & 0xFFFFF000) == 0x00780000:
                        found.append(hex(val))
        fuse_refs[name] = found

    assert fuse_refs["cmd_0x0_wb_read"] == ["0x7805b0"]
    assert fuse_refs["cmd_0x1_wb_blow"] == ["0x7805b0"]
    assert fuse_refs["cmd_0x7_rp_en"] == ["0x780198"]
    assert fuse_refs["cmd_0x8_rp_ignore"] == ["0x780158"]
    assert fuse_refs["cmd_0xb_secboot_p1"] == ["0x780350"]
    assert fuse_refs["cmd_0xb_secboot_p2"] == ["0x780188"]
    assert fuse_refs["cmd_0xb_secboot_p3"] == ["0x780158"]
    assert fuse_refs["cmd_0xd_rp_xbl"] == ["0x780168"]
    assert fuse_refs["cmd_0xe_rp_pil"] == ["0x780170", "0x780178"]
    assert fuse_refs["cmd_0xf_rp_rpm"] == ["0x780170"]
    assert fuse_refs["cmd_0x10_rp_tz"] == ["0x780170"]
    assert fuse_refs["cmd_0x11_rp_hyp"] == ["0x780178"]
    assert fuse_refs["cmd_0x12_rp_dp"] == ["0x780178"]
    assert fuse_refs["cmd_0x13_rp_devcfg"] == ["0x780178"]
    assert fuse_refs["cmd_0x15_rpmb_fuse"] == ["0x780178"]
    assert fuse_refs["cmd_0x18_ek_read"] == ["0x7805b0"]
    assert fuse_refs["cmd_0x19_1b_ek_write"] == ["0x7805b0"]

    # Verify ARM32 SVC #0x1400 trampoline at 0x16030..0x16060
    md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    svcs = [hex(i.address) for i in md_arm.disasm(mapper.read(0x16030, 0x30), 0x16030) if i.mnemonic == "svc"]
    assert svcs == ["0x16030", "0x16054"], f"Unexpected SVC sites: {svcs}"

    return {
        "elf_entry": hex(mapper.entry),
        "segments_count": mapper.phnum,
        "app_id": "0x888",
        "got": {
            "stack_chk_guard_ptr": hex(got_canary),
            "oem_pk_hash_table": hex(got_pk_table),
            "tima_rsa2048_key": hex(got_tima_pub),
        },
        "oem_pk_hash_rows": pk_rows,
        "qfprom_fuses_by_handler": fuse_refs,
        "svc_trampolines": svcs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit full JSON summary to stdout")
    args = parser.parse_args()

    results = {
        "xbl_loader": verify_xbl_loader(),
        "verified_boot_dxe": verify_verified_boot_dxe(),
        "tz_dxe": verify_tz_dxe(),
        "bksecapp": verify_bksecapp(),
    }

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("SM-A920F XBL_Loader / VerifiedBootDxe / TzDxe / bksecapp Verification PASSED")
        print(f"  xbl_loader.elf : entry={results['xbl_loader']['entry']} segs={results['xbl_loader']['segments_count']} sbl1_cfg={len(results['xbl_loader']['sbl1_config_table'])}")
        print(f"  VerifiedBootDxe: rev={results['verified_boot_dxe']['vb_protocol_revision']} methods={len(results['verified_boot_dxe']['vb_protocol_methods'])} smcs={results['verified_boot_dxe']['smc_ids_verified']}")
        print(f"  TzDxe          : qseecom_rev={results['tz_dxe']['qseecom_protocol_revision']} scm_rev={results['tz_dxe']['scm_protocol_revision']} smc_sites={len(results['tz_dxe']['smc_instruction_rvas'])}")
        print(f"  bksecapp.elf   : app_id={results['bksecapp']['app_id']} pk_rows={len(results['bksecapp']['oem_pk_hash_rows'])} fuse_handlers={len(results['bksecapp']['qfprom_fuses_by_handler'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
