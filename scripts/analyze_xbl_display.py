#!/usr/bin/env python3
"""Verify DisplayDxe.efi (SM-A920F / a9y18qlte XBL) architecture, panel detection,
embedded Samsung AMOLED XML configs, UEFI variables (DisplayPanelConfiguration,
DisplaySplashBufferInfo, UEFIDisplayInfo), and LinuxLoader.efi handoff.

Strictly read-only on extracted/, decomp/, and docs/.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

BASE_DIR = Path(__file__).resolve().parent.parent
DISPLAY_EFI = BASE_DIR / "extracted/F_XBL/dxe/DisplayDxe.efi"
DISPLAY_FUNCS_JSON = BASE_DIR / "decomp/XBL_DisplayDxe/functions.json"
DXE_MANIFEST = BASE_DIR / "extracted/F_XBL/dxe_manifest.json"
UEFIPLAT_CFG = BASE_DIR / "extracted/F_XBL/cfg/uefiplat.cfg"
UEFI_GUIDS_JSON = BASE_DIR / "extracted/uefi_guids.json"
LL_EFI = BASE_DIR / "extracted/F/LinuxLoader.efi"
LL_FUNCS_JSON = BASE_DIR / "decomp/F_LinuxLoader/functions.json"


KNOWN_GUID_LABELS = {
    "9042a9de-23dc-4a38-96fb-7aded080516a": "EfiGraphicsOutputProtocol",
    "09576e91-6d3f-11d2-8e39-00a0c969723b": "EfiDevicePathProtocol",
    "7bfa4293-7aa4-4375-b63c-b6aab786c43c": "QcomDisplayPwrCtrlProtocol",
    "f352021d-9593-4432-bf04-67b9f3b76008": "EfiDisplayPowerProtocol",
    "c0dd69ac-76ba-11e6-ab24-1fc7f5575f19": "QcomDisplayUtilsProtocol",
    "882f8c2b-9646-435f-8de5-f208ff80c1bd": "QcomTokenSpaceGuid",
    "157a5c45-21b2-43c5-ba7c-822fee5fe599": "QcomPlatformInfoProtocol",
    "b0760469-970c-487a-a4b5-28db7b45cef1": "QcomChipInfoProtocol",
    "4684800a-2755-4edc-b443-7f8ceb3239d3": "QcomPmicVersionProtocol",
    "ad9aec18-7bf0-4809-9e96-3012309f3df7": "QcomTlmmProtocol",
    "79d6c870-725e-489e-a0a1-27e7a5d0cb35": "QcomNpaProtocol",
    "b27ae8b1-3e10-4d07-ab5c-eb9a6dc6fa8f": "QcomI2CProtocol",
    "ce30ea4d-c78f-4606-9c3b-11efedcf6e87": "QcomPmicWledProtocol",
    "a966cc4f-ee6c-424d-a762-8ed3b5a4a501": "QcomPmicLabProtocol",
    "b7639e28-c06b-47f0-9a13-35eeba3b51f8": "QcomPmicLcdbProtocol",
    "55e2e265-cdb2-46df-88a5-600bedef9c62": "QcomPmicOledbProtocol",
    "241afae6-885f-4f6c-a7ea-c28eab79c3e5": "QcomClockProtocol",
    "fa5f306b-f47d-4ac4-a47d-882f8204ec30": "QcomSpmiProtocol",
    "c1bff82d-6c92-48fb-8355-c7fb4218a4ea": "QcomPmicIbbProtocol",
    "b1eb3d10-9d67-40ca-9559-f1488b1b2ddb": "QcomBlockIoRefreshEventGuid",
    "68c3b70d-0f96-4006-99f6-0fd211f5f2b2": "QcomUIIdleOnEventGuid",
    "30d39942-9556-4887-a943-bc63805d9d43": "QcomUIIdleOffEventGuid",
    "8bf5eaff-dbcf-449f-989b-a151cdd73da7": "QcomUIBrightnessLowEventGuid",
    "5bbd623c-dfda-425d-89ae-2e4e2ffe6363": "QcomUIBrightnessHighEventGuid",
}


def read_cstr(data: bytes, offset: int, max_len: int = 8192) -> str:
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    assert end != -1, f"Unterminated string at 0x{offset:x}"
    return data[offset:end].decode("ascii")


def read_utf16le(data: bytes, offset: int, max_chars: int = 128) -> str:
    out = []
    for i in range(max_chars):
        ch = struct.unpack_from("<H", data, offset + i * 2)[0]
        if ch == 0:
            break
        out.append(chr(ch))
    return "".join(out)


def parse_pe32plus(data: bytes) -> dict:
    assert data[:2] == b"MZ"
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_off : pe_off + 4] == b"PE\x00\x00"
    machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    assert machine == 0xAA64, f"Expected AArch64 0xAA64, got 0x{machine:x}"
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    assert magic == 0x20B
    entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
    image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sections):
        s_off = sec_off + i * 40
        name = data[s_off : s_off + 8].rstrip(b"\x00").decode("ascii")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<4I", data, s_off + 8)
        assert vaddr == rptr, f"Section {name} VA!=FileOffset (0x{vaddr:x} vs 0x{rptr:x})"
        sections.append({"name": name, "vaddr": f"0x{vaddr:x}", "vsize": f"0x{vsize:x}", "raw_off": f"0x{rptr:x}", "raw_size": f"0x{rsize:x}"})
    return {
        "file_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": f"0x{machine:x}",
        "image_base": f"0x{image_base:x}",
        "entry_point_rva": f"0x{entry_rva:x}",
        "sections": sections,
    }


def decode_depex(dep_hex: str) -> list[str]:
    raw = bytes.fromhex(dep_hex)
    i = 0
    guids = []
    while i < len(raw):
        op = raw[i]
        if op == 0x02:
            g = str(uuid.UUID(bytes_le=raw[i + 1 : i + 17])).lower()
            guids.append(f"{g} ({KNOWN_GUID_LABELS.get(g, 'Unknown')})")
            i += 17
        elif op in (0x03, 0x04, 0x05, 0x06, 0x07, 0x08):
            i += 1
        else:
            raise AssertionError(f"Unexpected DEPEX opcode 0x{op:02x}")
    return guids


def verify_uefiplat_display_reserved() -> dict:
    txt = UEFIPLAT_CFG.read_text(encoding="utf-8")
    m = re.search(
        r'^(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*"Display Reserved",\s*(.+)$',
        txt,
        re.MULTILINE,
    )
    assert m, "Display Reserved entry missing in uefiplat.cfg"
    base = int(m.group(1), 16)
    size = int(m.group(2), 16)
    assert base == 0x9D400000 and size == 0x02400000
    return {"base": hex(base), "size": hex(size), "size_mib": size // (1024 * 1024), "attrs": m.group(3).strip()}


def verify_vtables_and_guids(data: bytes) -> dict:
    vtables = {}
    for label, off, count in [
        ("EfiGraphicsOutputProtocol_0x36238", 0x36238, 4),
        ("QcomDisplayPwrCtrlProtocol_0x36258", 0x36258, 5),
        ("EfiDisplayPowerProtocol_0x36280", 0x36280, 4),
        ("QcomDisplayUtilsProtocol_0x3a920", 0x3A920, 6),
    ]:
        vals = struct.unpack_from(f"<{count}Q", data, off)
        vtables[label] = [f"0x{v:x}" for v in vals]

    assert vtables["EfiGraphicsOutputProtocol_0x36238"] == ["0x1c1c", "0x1cd8", "0x1eb4", "0x3aa68"]
    assert vtables["QcomDisplayPwrCtrlProtocol_0x36258"] == ["0x10000", "0x2208", "0x25f8", "0x2674", "0x270c"]
    assert vtables["EfiDisplayPowerProtocol_0x36280"] == ["0x10000", "0x2770", "0x2aec", "0x36298"]
    assert vtables["QcomDisplayUtilsProtocol_0x3a920"] == ["0x20000", "0x17230", "0x172a8", "0x173f4", "0x17400", "0x1740c"]

    guid_checks = {}
    for off in [
        0x21F00, 0x21F10, 0x21F20, 0x21F30, 0x21F40,
        0x36008, 0x36020, 0x36030, 0x360D0, 0x360E0, 0x360F0,
        0x36100, 0x36110, 0x36140, 0x36150, 0x36190,
        0x361A0, 0x361B0, 0x361C0, 0x361D0, 0x361E0, 0x361F0, 0x36200, 0x36210,
    ]:
        g = str(uuid.UUID(bytes_le=data[off : off + 16])).lower()
        guid_checks[f"0x{off:05x}"] = f"{g} ({KNOWN_GUID_LABELS.get(g, 'Other')})"
    return {"vtables": vtables, "guids": guid_checks}


def verify_panel_dt_table_and_xmls(data: bytes) -> dict:
    panels = []
    off = 0x31E30
    while off < 0x32F40:
        name = data[off : off + 0x40].split(b"\x00")[0].decode("ascii")
        panel_id = struct.unpack_from("<I", data, off + 0x40)[0]
        if not name and panel_id == 0:
            break
        dt_node = data[off + 0x44 : off + 0x84].split(b"\x00")[0].decode("ascii")
        intf, xml_ptr, xml_len, cfg_num, pll_mode, f0, f1, f2 = struct.unpack_from("<IQ6I", data, off + 0x84)
        panels.append(
            {
                "rva": f"0x{off:05x}",
                "panel_id": panel_id,
                "name": name,
                "dt_node": dt_node,
                "xml_ptr": f"0x{xml_ptr:05x}",
                "xml_len": xml_len,
                "cfg": cfg_num,
                "pll": pll_mode,
                "flags": [hex(f0), hex(f1), hex(f2)],
            }
        )
        off += 0xA8

    assert len(panels) == 25, f"Expected 25 DT panel entries, got {len(panels)}"
    assert panels[22]["panel_id"] == 27 and panels[22]["dt_node"] == "ss_dsi_panel_S6E3FA7_AMS628RF01_FHD"
    assert panels[24]["panel_id"] == 29 and panels[24]["dt_node"] == "ss_dsi_panel_PBA_BOOTING_FHD"

    # Parse Samsung AMOLED XMLs (AMS628RF01 @ 0x29e8b and AMS622MR01 @ 0x287a4)
    samsung_xmls = {}
    for label, xml_off, expected_size in [("AMS628RF01", 0x29E8B, 0x13FC), ("AMS622MR01", 0x287A4, 0x1206)]:
        xml_str = read_cstr(data, xml_off, max_len=8192)
        assert len(xml_str) + 1 == expected_size, f"{label}: len+1=0x{len(xml_str)+1:x} != 0x{expected_size:x}"
        # Extract key tags via regex (the embedded XML mixes DSIInitSequence raw text and attributes)
        tags = {}
        for tag in [
            "PanelName", "PanelDescription", "HorizontalActive", "HorizontalFrontPorch",
            "HorizontalBackPorch", "HorizontalSyncPulse", "VerticalActive", "VerticalFrontPorch",
            "VerticalBackPorch", "VerticalSyncPulse", "InterfaceType", "InterfaceColorFormat",
            "DSIChannelId", "DSIColorFormat", "DSITrafficMode", "DSILanes", "DSIRefreshRate",
            "DSIDSCEnable", "DSITECheckEnable", "DSITEUsingDedicatedTEPin", "DSITEvSyncStartPos",
            "DSIInitSequence", "DSITermSequence", "TLMMGPIODefaultHigh",
            "BacklightType", "BacklightPmicControlType",
        ]:
            m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml_str, re.DOTALL)
            if m:
                tags[tag] = " ".join(m.group(1).strip().split())
        samsung_xmls[label] = {"rva": f"0x{xml_off:05x}", "size_bytes": len(xml_str) + 1, "fields": tags}

    assert samsung_xmls["AMS628RF01"]["fields"]["HorizontalActive"] == "1080"
    assert samsung_xmls["AMS628RF01"]["fields"]["VerticalActive"] == "2220"
    assert samsung_xmls["AMS628RF01"]["fields"]["DSILanes"] == "4"
    assert samsung_xmls["AMS628RF01"]["fields"]["BacklightType"] == "3"
    return {"dt_panel_count": len(panels), "dt_panels": panels, "samsung_xmls": samsung_xmls}


def verify_instructions_and_constants(data: bytes) -> dict:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    # 1. entry (0x1130) -> bl 0x1160 (stack canary) -> b 0x103c (_ModuleEntryPoint -> 0x15d0)
    insns_1130 = [(hex(i.address), i.mnemonic, i.op_str) for i in md.disasm(data[0x1130:0x1160], 0x1130)]
    assert any(a == "0x1148" and m == "bl" and o == "#0x1160" for a, m, o in insns_1130), insns_1130
    assert any(a == "0x115c" and m == "b" and o == "#0x103c" for a, m, o in insns_1130), insns_1130

    # 2. kts1620 hw_rev reading at 0x193ec (pins 0x15, 0x16, 0x17)
    insns_193ec = [(hex(i.address), i.mnemonic, i.op_str) for i in md.disasm(data[0x193EC:0x19430], 0x193EC)]
    assert any(a == "0x193fc" and o == "w0, #0x15" for a, _, o in insns_193ec)
    assert any(a == "0x19408" and o == "w0, #0x16" for a, _, o in insns_193ec)
    assert any(a == "0x19414" and o == "w0, #0x17" for a, _, o in insns_193ec)

    # 3. FUN_000069d0 returns 4 (AMOLED peripheral power type)
    insns_69d0 = [(hex(i.address), i.mnemonic, i.op_str) for i in md.disasm(data[0x69D0:0x69D8], 0x69D0)]
    assert insns_69d0 == [("0x69d0", "mov", "w0, #4"), ("0x69d4", "ret", "")], insns_69d0

    # 4. UTF-16LE UEFI variable names in DisplayDxe.efi
    var_disp_cfg = read_utf16le(data, 0x23DD0)
    var_uefi_disp = read_utf16le(data, 0x277C0)
    var_splash = read_utf16le(data, 0x27BB0)
    var_override = read_utf16le(data, 0x27EE8)
    assert var_disp_cfg == "DisplayPanelConfiguration"
    assert var_uefi_disp == "UEFIDisplayInfo"
    assert var_splash == "DisplaySplashBufferInfo"
    assert var_override == "DisplayPanelOverride"

    # 5. MDSS base address table at 0x26818
    mdss_bases = [struct.unpack_from("<2I", data, 0x26818 + i * 8) for i in range(3)]
    assert all(base == 0x0C900000 for _, base in mdss_bases)

    # 6. Clock frequencies at 0x25ad0
    clocks = {}
    for off in range(0x25AD0, 0x25E90, 0x30):
        name = data[off : off + 0x1C].split(b"\x00")[0].decode("ascii")
        if name:
            freq = struct.unpack_from("<I", data, off + 0x1C)[0]
            clocks[name] = freq
    assert clocks["mmss_mdss_axi_clk"] == 240_000_000
    assert clocks["mmss_mdss_mdp_clk"] == 300_000_000

    # 7. kts1620 I2C pins (SDA=0x33=51, SCL=0x34=52) at 0x3a9b8
    kts_name = data[0x3A9B8:0x3A9C8].split(b"\x00")[0].decode("ascii")
    kts_sda, kts_scl = struct.unpack_from("<2I", data, 0x3A9C8)
    assert kts_name == "kts1620_i2c" and kts_sda == 51 and kts_scl == 52

    return {
        "entry_insns": insns_1130,
        "kts1620": {"name": kts_name, "sda_gpio": kts_sda, "scl_gpio": kts_scl, "rev_pins": [21, 22, 23]},
        "variables": {
            "0x23dd0": var_disp_cfg,
            "0x277c0": var_uefi_disp,
            "0x27bb0": var_splash,
            "0x27ee8": var_override,
        },
        "mdss_bases": [(hex(f), hex(b)) for f, b in mdss_bases],
        "clocks_hz": clocks,
        "cmd_strings": {
            "0x23e04": read_cstr(data, 0x23E04),
            "0x23e18": read_cstr(data, 0x23E18),
            "0x23e2c_order": list(struct.unpack_from("<3I", data, 0x23E2C)),
            "0x28142": read_cstr(data, 0x28142),
            "0x3311c": read_cstr(data, 0x3311C),
        },
    }


def verify_decomp_and_linuxloader_handoff(ll_data: bytes) -> dict:
    disp_fns = json.loads(DISPLAY_FUNCS_JSON.read_text(encoding="utf-8"))
    disp_rvas = {int(f["rva"], 16): f for f in disp_fns}
    required_disp_rvas = [
        0x103C, 0x1130, 0x1198, 0x1494, 0x1548, 0x1568, 0x1588, 0x15AC,
        0x15D0, 0x1C1C, 0x1CD8, 0x1EB4, 0x2208, 0x2408, 0x2674, 0x2770, 0x290C,
        0x6044, 0x636C, 0x6400, 0x669C, 0x6780, 0x6890, 0x69D8, 0x6C48, 0x6D10,
        0x6DAC, 0x6E4C, 0x6F34, 0x7134, 0x73F0, 0x76DC, 0x7C20, 0x7EDC, 0x80D4,
        0x816C, 0x8240, 0x114F0, 0x11A0C, 0x11ED4, 0x12384, 0x1264C, 0x12988,
        0x12A50, 0x12E84, 0x158F4, 0x1599C, 0x15BB0, 0x15FA0, 0x166A4, 0x16B7C,
        0x171AC, 0x171E8, 0x171FC, 0x1726C, 0x172A8, 0x1733C, 0x1740C, 0x193EC,
        0x19430, 0x195A8, 0x196F8, 0x19A08, 0x19C80, 0x19CC4, 0x1B840, 0x1BBBC,
        0x1C820, 0x203D8, 0x204FC,
    ]
    missing = [hex(r) for r in required_disp_rvas if r not in disp_rvas]
    assert not missing, f"Missing DisplayDxe RVAs in functions.json: {missing}"

    # Verify LinuxLoader.efi variables & functions
    ll_fns = json.loads(LL_FUNCS_JSON.read_text(encoding="utf-8"))
    ll_rvas = {int(f["rva"], 16) for f in ll_fns}
    for r in (0x16EF8, 0x241A0, 0x260B4):
        assert r in ll_rvas, f"Missing LinuxLoader RVA 0x{r:x}"

    assert read_utf16le(ll_data, 0x7B7F8) == "DisplayPanelConfiguration"
    assert read_utf16le(ll_data, 0x7F900) == "DisplaySplashBufferInfo"
    return {
        "displaydxe_function_count": len(disp_fns),
        "verified_displaydxe_rvas": len(required_disp_rvas),
        "linuxloader_var_0x7b7f8": "DisplayPanelConfiguration",
        "linuxloader_var_0x7f900": "DisplaySplashBufferInfo",
    }


def main() -> int:
    data = DISPLAY_EFI.read_bytes()
    ll_data = LL_EFI.read_bytes()
    dxe_manifest = json.loads(DXE_MANIFEST.read_text(encoding="utf-8"))
    disp_entry = next(d for d in dxe_manifest if d.get("ui_name") == "DisplayDxe")

    report = {
        "pe32plus": parse_pe32plus(data),
        "depex_guids": decode_depex(disp_entry["depex_hex"]),
        "uefiplat_display_reserved": verify_uefiplat_display_reserved(),
        "vtables_and_guids": verify_vtables_and_guids(data),
        "panel_dt_and_xmls": verify_panel_dt_table_and_xmls(data),
        "instructions_and_constants": verify_instructions_and_constants(data),
        "decomp_and_handoff": verify_decomp_and_linuxloader_handoff(ll_data),
    }

    assert report["pe32plus"]["file_size"] == 266240
    assert report["pe32plus"]["entry_point_rva"] == "0x1130"
    assert report["pe32plus"]["image_base"] == "0x0"

    print(json.dumps(report, indent=2))
    print("\nALL CHECKS PASSED", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
