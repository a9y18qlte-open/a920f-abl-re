#!/usr/bin/env python3
"""Extract and verify Samsung Odin protocol tables, Download Mode UI sources,
and Verified Boot / Sec_Auth_* / AVB artifacts from SM-A920F ABL binaries.

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

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

BASE_DIR = Path(__file__).resolve().parent.parent
ODIN_PATH = BASE_DIR / "extracted/F/Odin.efi"
LL_PATH = BASE_DIR / "extracted/F/LinuxLoader.efi"
META_PATH = BASE_DIR / "extracted/F/elf_mbn_metadata.json"
GUIDS_PATH = BASE_DIR / "extracted/uefi_guids.json"

# Expected RVAs verified in Ghidra 12.1.4 + Capstone disassembly
ODIN_ASCII_CMDS = {
    "ODIN": 0x0047B4,
    "ATQ0": 0x0067D0,
    "ROOTING": 0x006848,
    "DVIF": 0x0068C0,
    "SECCMD": 0x006F98,
}

ODIN_MAIN_JUMPTABLE_RVA = 0x55830   # 6 entries: cmd 0x64..0x69
ODIN_65_JUMPTABLE_RVA = 0x55860     # 4 entries: subcmd 0..3
ODIN_64_JUMPTABLE_RVA = 0x55880     # 11 entries: subcmd 0..0xa

BOOT_RESTORE_TABLE_RVA = 0x780F8    # 14 entries, stride 0x60
PIT_GUID_TABLE_RVA = 0x7863C        # 62 entries, stride 0x58
SECAUTH_PART_TABLE_RVA = 0x79BA8    # 37 named entries + 1 terminator, stride 0x40
SECAUTH_ENUM_BIN_RVA = 0x7A5F8      # binary type enum (ptr, str)
SECAUTH_ENUM_ERR_RVA = 0x7A678      # error/reason enum (ptr, str)

ODIN_EMC_RSA2048_SPKI_RVA = 0x5A670
LL_EMC_RSA2048_SPKI_RVA = 0x795F0
ODIN_SIGNER_RSA2048_SPKI_RVA = 0x5B1DC
LL_SIGNER_RSA2048_SPKI_RVA = 0x7A05B
RSA2048_SPKI_LEN = 0x126            # 294 bytes DER SubjectPublicKeyInfo

LL_AVB_OEM_KEY_RVA = 0x76CFB
LL_AVB_OEM_KEY_LEN = 0x408          # 1032 bytes AvbRSAPublicKeyHeader + RSA-4096

UI_BANNER_STRINGS = {
    0x5B573: " CURRENT BINARY: %a",
    0x5B587: " FRP LOCK : %a",
    0x5B59A: " OEM LOCK : %a",
    0x5B5A9: " RMM STATUS : %a",
    0x5B5BA: " KG STATUS : %a",
    0x5B5CE: " WARRANTY VOID : 0x%x (0x%x)",
    0x5B5EB: " WARRANTY VOID : 0x%x",
    0x5B601: " QUALCOMM SECUREBOOT : ENABLE ",
    0x5B63F: " QUALCOMM SECUREBOOT : 0x%x",
    0x5B678: " QUALCOMM SECUREBOOT : NONE",
    0x5B6D7: " RP SWREV : B%d(%d,%d,%d,%d,%d) K%d S%d",
    0x5B6FF: " RP SWREV : TEST DEVICE",
    0x5B717: " SECURE DOWNLOAD : ENABLE",
}

JPEG_ASSET_RVAS = [0x7AAD4, 0xA5E18, 0xB26F4]


def read_cstr(blob: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(blob):
        raise ValueError(f"Invalid string offset: {offset:#x}")
    end = blob.find(b"\x00", offset)
    if end == -1:
        raise ValueError(f"Unterminated string at {offset:#x}")
    return blob[offset:end].decode("ascii", errors="strict")


def decode_guid(blob: bytes, offset: int) -> str:
    return str(uuid.UUID(bytes_le=blob[offset : offset + 16]))


def decode_adrp_add(ins_adrp, ins_add) -> int | None:
    if ins_adrp.mnemonic == "adrp" and ins_add.mnemonic == "add":
        page = int(ins_adrp.op_str.split("#")[-1], 16)
        imm = int(ins_add.op_str.split("#")[-1], 16)
        return page + imm
    return None


def extract_usb_descriptors(odin: bytes) -> dict[str, Any]:
    hs_dev = odin[0x78038 : 0x78038 + 18]
    ss_dev = odin[0x7804A : 0x7804A + 18]
    vid_hs, pid_hs = struct.unpack_from("<HH", hs_dev, 8)
    vid_ss, pid_ss = struct.unpack_from("<HH", ss_dev, 8)
    assert vid_hs == 0x04E8 and pid_hs == 0x685D, f"Unexpected HS VID/PID: {vid_hs:#x}/{pid_hs:#x}"
    assert vid_ss == 0x04E8 and pid_ss == 0x685D, f"Unexpected SS VID/PID: {vid_ss:#x}/{pid_ss:#x}"

    # String descriptors pointed to around 0x557xx / 0x78010
    str_ptrs = struct.unpack_from("<QQQ", odin, 0x78010)
    # Verify actual UTF-16LE / USB string descriptors in 0x55700..0x55800
    usb_strings = []
    for off in str_ptrs:
        ln = odin[off]
        dtype = odin[off + 1]
        if dtype == 3 and ln >= 2:
            raw = odin[off + 2 : off + ln]
            try:
                usb_strings.append(raw.decode("utf-16le"))
            except UnicodeDecodeError:
                usb_strings.append(raw.hex())

    return {
        "controller_init_event_guid": decode_guid(odin, 0x552E8),
        "usb_device_protocol_guid": decode_guid(odin, 0x552F8),
        "hs_device_desc": {"vid": f"0x{vid_hs:04x}", "pid": f"0x{pid_hs:04x}"},
        "ss_device_desc": {"vid": f"0x{vid_ss:04x}", "pid": f"0x{pid_ss:04x}"},
        "str_table_rvas": [f"0x{x:x}" for x in str_ptrs],
        "rx_tx_buf_size": 0x100000,
        "odin_staging_buf_size": 0x40000000,
    }


def extract_jump_tables(odin: bytes) -> dict[str, Any]:
    main_targets_raw = struct.unpack_from("<6Q", odin, ODIN_MAIN_JUMPTABLE_RVA)
    sub65_targets_raw = struct.unpack_from("<4Q", odin, ODIN_65_JUMPTABLE_RVA)
    sub64_targets_raw = struct.unpack_from("<11Q", odin, ODIN_64_JUMPTABLE_RVA)

    main_targets = {f"0x{0x64 + i:02x}": f"0x{addr:05x}" for i, addr in enumerate(main_targets_raw)}
    sub65_targets = {f"0x{i:02x}": f"0x{addr:05x}" for i, addr in enumerate(sub65_targets_raw)}
    sub64_targets = {f"0x{i:02x}": f"0x{addr:05x}" for i, addr in enumerate(sub64_targets_raw)}

    assert main_targets["0x64"] == "0x04a54"
    assert main_targets["0x65"] == "0x04b00"
    assert main_targets["0x66"] == "0x04b68"
    assert main_targets["0x67"] == "0x04bb8"
    assert main_targets["0x68"] == "0x04c94"
    assert main_targets["0x69"] == "0x04ccc"

    assert sub64_targets["0x00"] == "0x04a78"
    assert sub64_targets["0x01"] == "0x0567c"
    assert sub64_targets["0x02"] == "0x056b8"
    assert sub64_targets["0x05"] == "0x05760"
    assert sub64_targets["0x07"] == "0x057a4"
    assert sub64_targets["0x09"] == "0x057f0"
    assert sub64_targets["0x0a"] == "0x05868"

    assert sub65_targets["0x00"] == "0x04b28"
    assert sub65_targets["0x01"] == "0x05910"
    assert sub65_targets["0x02"] == "0x05984"
    assert sub65_targets["0x03"] == "0x05a10"

    return {
        "ascii_cmds": {k: f"0x{v:05x}" for k, v in ODIN_ASCII_CMDS.items()},
        "main_cmd_table_0x55830": main_targets,
        "cmd_0x64_subtable_0x55880": sub64_targets,
        "cmd_0x65_subtable_0x55860": sub65_targets,
    }


def extract_partition_tables(odin: bytes) -> dict[str, Any]:
    boot_restore = []
    for i in range(14):
        off = BOOT_RESTORE_TABLE_RVA + i * 0x60
        name = odin[off : off + 0x48].split(b"\x00", 1)[0].decode("ascii")
        boot_restore.append({"index": i, "rva": f"0x{off:05x}", "name": name})
    assert [x["name"] for x in boot_restore] == [
        "xbl", "rpm", "tz", "hyp", "pmic", "abl", "devcfg",
        "cmnlib", "cmnlib64", "keymaster", "apdp", "sec", "bksecapp", "btd",
    ]

    pit_guids = []
    for i in range(62):
        off = PIT_GUID_TABLE_RVA + i * 0x58
        name = odin[off : off + 0x48].split(b"\x00", 1)[0].decode("ascii")
        guid = decode_guid(odin, off + 0x48)
        pit_guids.append({"index": i, "rva": f"0x{off:05x}", "name": name, "guid": guid})
    assert pit_guids[0]["name"] == "modemst1" and pit_guids[-1]["name"] == "linux"

    secauth_parts = []
    for i in range(37):
        off = SECAUTH_PART_TABLE_RVA + i * 0x40
        vals = struct.unpack_from("<8I4Q", odin, off)
        name = read_cstr(odin, vals[8])
        secauth_parts.append({
            "index": i,
            "rva": f"0x{off:05x}",
            "name": name,
            "image_type": vals[1],
            "is_sparse_flag": bool((vals[10] >> 32) & 1),
        })
    assert secauth_parts[0]["name"] == "xbl"
    assert secauth_parts[26]["name"] == "system" and secauth_parts[26]["is_sparse_flag"] is True
    assert secauth_parts[36]["name"] == "dqmdbg"
    term_vals = struct.unpack_from("<8I4Q", odin, SECAUTH_PART_TABLE_RVA + 37 * 0x40)
    assert term_vals[1] == 0 and read_cstr(odin, term_vals[8]) == ""

    bin_enum = {}
    for i in range(7):
        off = SECAUTH_ENUM_BIN_RVA + i * 16
        val, ptr = struct.unpack_from("<QQ", odin, off)
        bin_enum[val] = read_cstr(odin, ptr)

    err_enum = {}
    for i in range(15):
        off = SECAUTH_ENUM_ERR_RVA + i * 16
        val, ptr = struct.unpack_from("<QQ", odin, off)
        if ptr == 0:
            break
        err_enum[val] = read_cstr(odin, ptr)

    return {
        "boot_restore_table_count": len(boot_restore),
        "boot_restore_partitions": boot_restore,
        "pit_guid_table_count": len(pit_guids),
        "pit_guid_table_sample": pit_guids[:6] + pit_guids[-4:],
        "secauth_policy_table_count": len(secauth_parts),
        "secauth_policy_partitions": secauth_parts,
        "secauth_image_types": bin_enum,
        "secauth_error_reasons": err_enum,
    }


def verify_ui_and_crypto(odin: bytes, ll: bytes) -> dict[str, Any]:
    for rva, expected in UI_BANNER_STRINGS.items():
        actual = read_cstr(odin, rva)
        assert actual == expected, f"UI string mismatch at {rva:#x}: {actual!r} != {expected!r}"

    for rva in JPEG_ASSET_RVAS:
        assert odin[rva : rva + 4] == b"\xff\xd8\xff\xe0", f"Expected JFIF JPEG header at {rva:#x}"

    odin_emc_spki = odin[ODIN_EMC_RSA2048_SPKI_RVA : ODIN_EMC_RSA2048_SPKI_RVA + RSA2048_SPKI_LEN]
    ll_emc_spki = ll[LL_EMC_RSA2048_SPKI_RVA : LL_EMC_RSA2048_SPKI_RVA + RSA2048_SPKI_LEN]
    assert odin_emc_spki == ll_emc_spki, "Odin.efi and LinuxLoader.efi EMC RSA-2048 SPKI mismatch"
    assert odin_emc_spki[:4] == b"\x30\x82\x01\x22", "Invalid EMC DER SPKI header"

    odin_signer_spki = odin[ODIN_SIGNER_RSA2048_SPKI_RVA : ODIN_SIGNER_RSA2048_SPKI_RVA + RSA2048_SPKI_LEN]
    ll_signer_spki = ll[LL_SIGNER_RSA2048_SPKI_RVA : LL_SIGNER_RSA2048_SPKI_RVA + RSA2048_SPKI_LEN]
    assert odin_signer_spki == ll_signer_spki, "Odin.efi and LinuxLoader.efi Signer RSA-2048 SPKI mismatch"
    assert odin_signer_spki[:4] == b"\x30\x82\x01\x22", "Invalid Signer DER SPKI header"

    avb_bits, avb_n0inv = struct.unpack_from(">II", ll, LL_AVB_OEM_KEY_RVA)
    assert avb_bits == 4096, f"Unexpected AVB key bits: {avb_bits}"

    # Verify LinuxLoader AvbOps vtable pointers in FUN_0000452c
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(md.disasm(ll[0x452C:0x4608], 0x452C))
    assert any(i.mnemonic == "mov" and "#0x58" in i.op_str for i in insns), "AvbOps size 0x58 check failed"

    return {
        "ui_banner_strings_verified": len(UI_BANNER_STRINGS),
        "jpeg_asset_rvas": [f"0x{x:05x}" for x in JPEG_ASSET_RVAS],
        "emc_rsa2048_spki_sha256": hashlib.sha256(odin_emc_spki).hexdigest(),
        "odin_emc_rsa2048_spki_rva": f"0x{ODIN_EMC_RSA2048_SPKI_RVA:05x}",
        "ll_emc_rsa2048_spki_rva": f"0x{LL_EMC_RSA2048_SPKI_RVA:05x}",
        "signer_rsa2048_spki_sha256": hashlib.sha256(odin_signer_spki).hexdigest(),
        "odin_signer_rsa2048_spki_rva": f"0x{ODIN_SIGNER_RSA2048_SPKI_RVA:05x}",
        "ll_signer_rsa2048_spki_rva": f"0x{LL_SIGNER_RSA2048_SPKI_RVA:05x}",
        "ll_avb_oem_key": {
            "rva": f"0x{LL_AVB_OEM_KEY_RVA:05x}",
            "size": LL_AVB_OEM_KEY_LEN,
            "key_num_bits": avb_bits,
            "n0inv": f"0x{avb_n0inv:08x}",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print full JSON report")
    args = parser.parse_args()

    odin = ODIN_PATH.read_bytes()
    ll = LL_PATH.read_bytes()
    meta = json.loads(META_PATH.read_text())
    guids = json.loads(GUIDS_PATH.read_text())

    report = {
        "firmware_version": meta.get("samsung_signer_footer", {}).get("build_id"),
        "odin_sha256": hashlib.sha256(odin).hexdigest(),
        "linuxloader_sha256": hashlib.sha256(ll).hexdigest(),
        "usb": extract_usb_descriptors(odin),
        "protocol": extract_jump_tables(odin),
        "partitions": extract_partition_tables(odin),
        "ui_and_crypto": verify_ui_and_crypto(odin, ll),
        "uefi_guid_count": len(guids),
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Odin.efi SHA256      : {report['odin_sha256']}")
        print(f"LinuxLoader.efi SHA256: {report['linuxloader_sha256']}")
        print(f"USB VID:PID          : {report['usb']['hs_device_desc']['vid']}:{report['usb']['hs_device_desc']['pid']}")
        print(f"USB Device GUID      : {report['usb']['usb_device_protocol_guid']}")
        print(f"Main Cmd Table       : {report['protocol']['main_cmd_table_0x55830']}")
        print(f"Cmd 0x64 Subtable    : {report['protocol']['cmd_0x64_subtable_0x55880']}")
        print(f"Cmd 0x65 Subtable    : {report['protocol']['cmd_0x65_subtable_0x55860']}")
        print(f"Boot Restore Entries : {report['partitions']['boot_restore_table_count']}")
        print(f"PIT->GUID Entries    : {report['partitions']['pit_guid_table_count']}")
        print(f"SecAuth Partitions   : {report['partitions']['secauth_policy_table_count']}")
        print(f"UI Banner Strings OK : {report['ui_and_crypto']['ui_banner_strings_verified']}")
        print(f"Shared EMC SPKI      : {report['ui_and_crypto']['emc_rsa2048_spki_sha256']}")
        print(f"Shared Signer SPKI   : {report['ui_and_crypto']['signer_rsa2048_spki_sha256']}")
        print(f"AVB OEM Key Bits     : {report['ui_and_crypto']['ll_avb_oem_key']['key_num_bits']} (n0inv={report['ui_and_crypto']['ll_avb_oem_key']['n0inv']})")
        print("ALL ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
