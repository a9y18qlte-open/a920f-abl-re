#!/usr/bin/env python3
"""Verify and extract boot.img, DTB/DTBO, kernel handoff, and cmdline facts
from SM-A920F (a9y18qlte) LinuxLoader.efi and its Ghidra decompilation.

Strictly read-only on extracted/ and decomp/.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

BASE_DIR = Path(__file__).resolve().parent.parent
EFI_PATH = BASE_DIR / "extracted/F/LinuxLoader.efi"
FUNCS_JSON = BASE_DIR / "decomp/F_LinuxLoader/functions.json"


def read_cstr(data: bytes, offset: int, max_len: int = 256) -> str | None:
    if offset <= 0 or offset >= len(data):
        return None
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        return None
    raw = data[offset:end]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
        return text
    return None


def disasm_range(md: Cs, data: bytes, start: int, end: int):
    return list(md.disasm(data[start:end], start))


def extract_snprintf_formats(md: Cs, data: bytes, start: int, end: int):
    """Extract all calls to FUN_00004814 (snprintf) and resolved x2 format strings."""
    adrps: dict[str, int] = {}
    recent_calls: list[int] = []
    results = []
    for insn in md.disasm(data[start:end], start):
        if insn.mnemonic == "adrp":
            reg, imm = insn.op_str.split(", ")
            adrps[reg.strip()] = int(imm.lstrip("#"), 16)
        elif insn.mnemonic == "add" and ", #" in insn.op_str:
            parts = [p.strip() for p in insn.op_str.split(",")]
            if len(parts) == 3 and parts[1] in adrps:
                adrps[parts[0]] = adrps[parts[1]] + int(parts[2].lstrip("#"), 16)
        elif insn.mnemonic == "bl":
            target = int(insn.op_str.lstrip("#"), 16)
            if target == 0x4814:
                x2 = adrps.get("x2")
                fmt = read_cstr(data, x2) if x2 is not None else None
                if fmt and fmt not in ("%a", " %a"):
                    results.append((insn.address, x2, fmt, recent_calls[-4:]))
            else:
                recent_calls.append(target)
    return results


def parse_pe_info(data: bytes) -> dict:
    assert data[:2] == b"MZ", "Expected MZ DOS header"
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_off : pe_off + 4] == b"PE\x00\x00", "Expected PE signature"
    machine, num_sections, _, _, _, opt_hdr_size, _ = struct.unpack_from(
        "<HHIIIHH", data, pe_off + 4
    )
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    assert magic == 0x20B, f"Expected PE32+ (0x20B), got 0x{magic:x}"
    entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
    image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
    return {
        "machine": f"0x{machine:x}",
        "num_sections": num_sections,
        "entry_rva": f"0x{entry_rva:x}",
        "image_base": f"0x{image_base:x}",
        "file_size": len(data),
    }


def verify_instructions(md: Cs, data: bytes) -> dict:
    checks = {}

    # 1. BootLinux return -> unconditional Download Mode (0x1b34)
    insns = disasm_range(md, data, 0x2144, 0x2150)
    mnems = [(hex(i.address), i.mnemonic, i.op_str) for i in insns]
    assert any(i.address == 0x2148 and i.mnemonic == "bl" and i.op_str == "#0x1db2c" for i in insns), mnems
    assert any(i.address == 0x214C and i.mnemonic == "b" and i.op_str == "#0x1b34" for i in insns), mnems
    checks["bootlinux_fallthrough_to_dload"] = mnems

    # 2. AVB version = 3 (NO_AVB) in LoadImageAndAuth (FUN_00002154)
    insns = disasm_range(md, data, 0x23EC, 0x2408)
    assert any(i.address == 0x23F0 and i.mnemonic == "mov" and i.op_str == "w9, #3" for i in insns), insns
    assert any(i.address == 0x2400 and i.mnemonic == "str" and i.op_str == "w9, [x19, #0x438]" for i in insns), insns
    checks["avb_version_no_avb"] = [(hex(i.address), f"{i.mnemonic} {i.op_str}") for i in insns]

    # 3. 64-bit & 32-bit kernel entry registers in BootLinux (FUN_0001db2c)
    insns64 = disasm_range(md, data, 0x1ECC0, 0x1ECD4)
    seq64 = [(hex(i.address), f"{i.mnemonic} {i.op_str}") for i in insns64]
    assert seq64 == [
        ("0x1ecc0", "ldp x0, x18, [sp, #0x20]"),
        ("0x1ecc4", "ldr x1, [sp, #0x18]"),
        ("0x1ecc8", "mov x3, xzr"),
        ("0x1eccc", "sub x2, x18, x1"),
        ("0x1ecd0", "blr x18"),
    ], seq64
    insns32 = disasm_range(md, data, 0x1ECD8, 0x1ECE8)
    seq32 = [(hex(i.address), f"{i.mnemonic} {i.op_str}") for i in insns32]
    assert seq32 == [
        ("0x1ecd8", "ldr x2, [sp, #0x20]"),
        ("0x1ecdc", "mov w0, wzr"),
        ("0x1ece0", "mov w1, wzr"),
        ("0x1ece4", "blr x25"),
    ], seq32
    checks["kernel_handoff_64"] = seq64
    checks["kernel_handoff_32"] = seq32

    # 4. BootLinux DTBO path (0x1e484..0x1e530)
    insns_dtbo = disasm_range(md, data, 0x1E484, 0x1E534)
    bls_dtbo = [(hex(i.address), i.op_str) for i in insns_dtbo if i.mnemonic == "bl"]
    assert bls_dtbo == [
        ("0x1e484", "#0x2a788"),
        ("0x1e4ac", "#0x21624"),
        ("0x1e4b8", "#0x1faf4"),
        ("0x1e4d0", "#0x226c4"),
        ("0x1e4dc", "#0x39a9c"),
        ("0x1e4e8", "#0x2f450"),
        ("0x1e4f4", "#0x38800"),
        ("0x1e504", "#0x2f450"),
        ("0x1e514", "#0x2f450"),
        ("0x1e528", "#0x38924"),
    ], bls_dtbo
    checks["bootlinux_dtbo_calls"] = bls_dtbo

    # 5. ValidateDtbo magic 0xd7b7ab1e and max 24 MiB check (0x2aa8c..0x2aab8)
    insns_val = disasm_range(md, data, 0x2AA8C, 0x2AAB8)
    val_seq = [(hex(i.address), f"{i.mnemonic} {i.op_str}") for i in insns_val]
    assert any(i.address == 0x2AA90 and i.op_str == "w19, #0xab1e" for i in insns_val), val_seq
    assert any(i.address == 0x2AA94 and i.op_str == "w19, #0xd7b7, lsl #16" for i in insns_val), val_seq
    assert any(i.address == 0x2AAA0 and i.mnemonic == "b.ne" and i.op_str == "#0x2ab18" for i in insns_val), val_seq
    checks["validate_dtbo_magic"] = val_seq

    # 6. Exact DTB match mask 0x1c150000 in FUN_00021624 & 0x1b flag in FUN_000226c4
    insns_21624 = disasm_range(md, data, 0x216B0, 0x21714)
    assert any(i.address == 0x216FC and i.mnemonic == "mov" and i.op_str == "w2, #0x1c" for i in insns_21624)
    assert any(i.address == 0x216B8 and i.mnemonic == "mov" and i.op_str == "w27, #0x1c150000" for i in insns_21624)
    assert any(i.address == 0x2170C and i.mnemonic == "bic" and i.op_str == "w9, w27, w8" for i in insns_21624)
    insns_226c4 = disasm_range(md, data, 0x22798, 0x22800)
    assert any(i.address == 0x227A0 and i.mnemonic == "mov" and i.op_str == "w22, #0x1b" for i in insns_226c4)
    checks["dtbo_match_flags"] = {"FUN_00021624_mask": "0x1c150000", "FUN_00021624_mode": "0x1c", "FUN_000226c4_mode": "0x1b"}

    # 7. Param partition offsets in 0x19204, 0x192c4, 0x193a0, 0x194b0
    param_offsets = {}
    for addr, name in [
        (0x19204, "upload_offset"),
        (0x192C4, "carrierid_param_offset"),
        (0x193A0, "sales_param_offset"),
        (0x194B0, "prototype_param_offset"),
    ]:
        insns_p = disasm_range(md, data, addr, addr + 0x44)
        adds = [i.op_str for i in insns_p if i.mnemonic == "add" and i.op_str.startswith("w0, w0, #")]
        assert len(adds) == 1, f"Unexpected add in {name}: {adds}"
        param_offsets[name] = adds[0].split("#")[1]
    assert param_offsets == {
        "upload_offset": "0x3f4",
        "carrierid_param_offset": "0x1cc",
        "sales_param_offset": "0x1d0",
        "prototype_param_offset": "0x1dc",
    }, param_offsets
    checks["param_offsets"] = param_offsets

    # 8. Hardcoded sec_log / sec_dbg / sec_dbg_ex_info constants before snprintf in FUN_000706bc
    sec_mem = {}
    for label, start, end in [
        ("sec_log", 0x70E54, 0x70E78),
        ("sec_dbg", 0x70F54, 0x70F78),
        ("sec_dbg_ex_info", 0x710C0, 0x710E4),
    ]:
        sec_mem[label] = [(hex(i.address), f"{i.mnemonic} {i.op_str}") for i in disasm_range(md, data, start, end)]
    checks["sec_mem_regions"] = sec_mem

    return checks


def main() -> int:
    data = EFI_PATH.read_bytes()
    funcs = json.loads(FUNCS_JSON.read_text())
    func_map = {f["rva"]: f for f in funcs}

    pe_info = parse_pe_info(data)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    required_rvas = [
        "0x1574", "0x1794", "0x2154", "0x452c", "0x6ba4", "0x7054", "0x7148",
        "0x16740", "0x167f4", "0x18388", "0x1bce0", "0x1be28", "0x1c424",
        "0x1d4e0", "0x1db2c", "0x1ed20", "0x1ee3c", "0x1f318", "0x1f6e0",
        "0x1fa38", "0x1faf4", "0x1fb3c", "0x21624", "0x21888", "0x226c4",
        "0x22938", "0x22b5c", "0x234e8", "0x23b5c", "0x23d78", "0x241a0",
        "0x24d28", "0x251bc", "0x25d54", "0x260b4", "0x2a788", "0x2b914",
        "0x38800", "0x38924", "0x6f444", "0x70448", "0x706bc",
    ]
    missing = [r for r in required_rvas if r not in func_map]
    assert not missing, f"Missing expected functions: {missing}"

    verified_insts = verify_instructions(md, data)

    # Verify verifiedbootstate string table at 0x9fa60..0x9fa80
    vb_states = []
    for i in range(4):
        ptr = struct.unpack_from("<Q", data, 0x9FA60 + i * 8)[0]
        vb_states.append(read_cstr(data, ptr))
    assert vb_states == ["green", "yellow", "orange", "red"], vb_states

    # Verify key embedded strings
    for s in [
        b"ANDROID!",
        b"UNCOMPRESSED_IMG",
        b"SM-A920F",
        b"A920FXXS7CVH1",
        b"A9Y18QLTE",
        b"Exact DTB match found. DTBO search is not required\n",
        b"Error: Board Dtbo blob not found\n",
        b"ufdt apply overlay failed\n",
        b"Dtbo hdr magic mismatch %x, with %x\n",
    ]:
        assert data.find(s) != -1, f"String not found: {s!r}"

    # Verify ARM64 kernel magic check at 0x1dff0 (+0x38 in Image header)
    insns_arm64 = disasm_range(md, data, 0x1DFF0, 0x1DFFC)
    assert any(i.address == 0x1DFF0 and i.mnemonic == "ldr" and i.op_str == "w0, [x22, #0x38]" for i in insns_arm64)

    # Extract all snprintf cmdline fragments from FUN_000260b4, FUN_00025d54, FUN_000706bc
    f25d = func_map["0x25d54"]
    f260 = func_map["0x260b4"]
    f706 = func_map["0x706bc"]
    cmd_root = extract_snprintf_formats(md, data, 0x25D54, 0x25D54 + f25d["size"])
    cmd_qcom = extract_snprintf_formats(md, data, 0x260B4, 0x260B4 + f260["size"])
    cmd_sec = extract_snprintf_formats(md, data, 0x706BC, 0x706BC + f706["size"])

    print("[PE Info]", json.dumps(pe_info, indent=2))
    print(f"[Verified Functions] {len(required_rvas)}/{len(required_rvas)} present in functions.json")
    print("[Verified Boot States @ 0x9fa60]", vb_states)
    print("[Param Offsets]", verified_insts["param_offsets"])
    print("[Kernel Handoff 64-bit]", verified_insts["kernel_handoff_64"])
    print("[Kernel Handoff 32-bit]", verified_insts["kernel_handoff_32"])
    print("[DTBO Match Flags]", verified_insts["dtbo_match_flags"])
    print("[BootLinux -> Download Mode]", verified_insts["bootlinux_fallthrough_to_dload"])

    print(f"\n[FUN_00025d54 root= snprintf formats ({len(cmd_root)})]")
    for call_rva, str_rva, fmt, _ in cmd_root:
        print(f"  0x{call_rva:05x} (str 0x{str_rva:05x}): {fmt!r}")

    print(f"\n[FUN_000260b4 UpdateCmdLine snprintf formats ({len(cmd_qcom)})]")
    for call_rva, str_rva, fmt, _ in cmd_qcom:
        print(f"  0x{call_rva:05x} (str 0x{str_rva:05x}): {fmt!r}")

    print(f"\n[FUN_000706bc sec_update_cmdline snprintf formats ({len(cmd_sec)})]")
    for call_rva, str_rva, fmt, calls in cmd_sec:
        c_str = ",".join(f"0x{c:x}" for c in calls)
        print(f"  0x{call_rva:05x} (str 0x{str_rva:05x}): {fmt!r}  (recent bl: {c_str})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
