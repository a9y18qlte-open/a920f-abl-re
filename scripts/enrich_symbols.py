#!/usr/bin/env python3
"""Post-process Ghidra ExportUefiAbl outputs to recover EDK2/Samsung symbols,
source-file ownership, log-derived function names, and UEFI protocol call xrefs."""

import json
import re
import sys
import uuid
from collections import defaultdict
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent

FUNC_HDR_RE = re.compile(
    r"^// === FUNC (\S+) @ RVA (0x[0-9a-fA-F]+) \(VA 0x[0-9a-fA-F]+, size 0x[0-9a-fA-F]+\) ===$"
)
SRC_PATH_RE = re.compile(r"/home/dpi/[^\s\"']+?/([A-Za-z0-9_.-]+\.[chS])")
PROTO_CALL_RE = re.compile(
    r"->(LocateProtocol|LocateHandleBuffer|LocateHandle|OpenProtocol|HandleProtocol|InstallProtocolInterface)\)?\s*\(([^;]+?)\)"
)
LOG_PREFIX_RE = re.compile(r"^([A-Z][A-Za-z0-9_]{3,40}):\s")


def split_decomp_by_rva(all_decomp_path: Path):
    blocks = {}
    cur_rva = None
    cur_lines = []
    with all_decomp_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = FUNC_HDR_RE.match(line.rstrip("\n"))
            if m:
                if cur_rva is not None:
                    blocks[cur_rva] = "\n".join(cur_lines)
                cur_rva = m.group(2).lower()
                cur_lines = [line.rstrip("\n")]
            elif cur_rva is not None:
                cur_lines.append(line.rstrip("\n"))
        if cur_rva is not None:
            blocks[cur_rva] = "\n".join(cur_lines)
    return blocks


def extract_guid_at_rva(efi_bytes: bytes, rva_hex: str):
    try:
        off = int(rva_hex, 16)
    except ValueError:
        return None
    if 0 <= off and off + 16 <= len(efi_bytes):
        raw = efi_bytes[off : off + 16]
        try:
            return str(uuid.UUID(bytes_le=raw))
        except Exception:
            return None
    return None


def enrich_module(decomp_dir: Path, efi_path: Path):
    funcs_path = decomp_dir / "functions.json"
    all_c_path = decomp_dir / "all_decomp.c"
    if not funcs_path.exists() or not all_c_path.exists():
        raise FileNotFoundError(f"Missing functions.json or all_decomp.c in {decomp_dir}")

    funcs = json.loads(funcs_path.read_text(encoding="utf-8"))
    decomp_blocks = split_decomp_by_rva(all_c_path)
    efi_bytes = efi_path.read_bytes() if efi_path.exists() else b""

    by_rva = {f["rva"].lower(): f for f in funcs}
    primitives = {}
    by_source = defaultdict(list)
    enriched = {}
    proto_xrefs = []

    # 1. Identify entry & key primitives
    entry_key = "0x1000" if "0x1000" in by_rva else ("0x1130" if "0x1130" in by_rva else None)
    if entry_key:
        primitives[entry_key] = "_ModuleEntryPoint"
        callees = by_rva[entry_key].get("callees", [])
        if len(callees) >= 3:
            primitives[callees[0].lower()] = "ProcessLibraryConstructorList"
            primitives[callees[1].lower()] = "ProcessModuleEntryPointList_or_Main"
            primitives[callees[2].lower()] = "ProcessLibraryDestructorList"

    for f in funcs:
        rva = f["rva"].lower()
        strs = f.get("strings", [])
        joined = "\n".join(strs)
        code = decomp_blocks.get(rva, "")

        # Detect DebugAssert / DebugPrint / PrintLib / Memory primitives
        if "ASSERT %a(%d): %a" in joined or "ASSERT " in joined and "(%d):" in joined:
            primitives[rva] = "DebugAssert"
        elif "UefiBootServicesTableLib.c" in joined and "gBS != ((void *)0)" in joined or "gST != NULL" in joined or "gBS != NULL" in joined:
            primitives[rva] = "UefiBootServicesTableLibConstructor"
        elif "UefiRuntimeServicesTableLib.c" in joined:
            primitives[rva] = "UefiRuntimeServicesTableLibConstructor"
        elif "ERROR: Failed to locate" in joined and "BootServices" not in joined and f["size"] < 0x120:
            pass
        elif "AvbGetSizeOfPartition" in joined:
            primitives[rva] = "AvbGetSizeOfPartition"
        elif "AvbGetUniqueGuidForPartition" in joined:
            primitives[rva] = "AvbGetUniqueGuidForPartition"
        elif "AppendVBCmdLine" in joined:
            primitives[rva] = "AppendVBCmdLine"
        elif "NoAVBLoadDtboImage" in joined:
            primitives[rva] = "NoAVBLoadDtboImage"

        # Source file hint
        src_files = sorted(set(SRC_PATH_RE.findall(joined)))
        for sf in src_files:
            by_source[sf].append(rva)

        # Log-derived function hints
        log_hints = []
        for s in strs:
            m = LOG_PREFIX_RE.match(s)
            if m:
                tok = m.group(1)
                if tok not in ("ERROR", "INFO", "DEBUG", "WARN", "WARNING", "ASSERT", "FAILED", "SUCCESS"):
                    log_hints.append(tok)

        suggested = primitives.get(rva)
        if not suggested and f["name"] != f"FUN_{rva[2:].zfill(8)}" and not f["name"].startswith("FUN_"):
            suggested = f["name"]
        if not suggested and log_hints:
            # Prefer a single consistent CamelCase prefix
            suggested = f"cand_{log_hints[0]}"

        # Extract BootServices protocol calls
        for pm in PROTO_CALL_RE.finditer(code):
            op = pm.group(1)
            args_str = " ".join(pm.group(2).split())
            g_ref = None
            g_uuid = None
            gm = re.search(r"&?(gGuid_[A-Za-z0-9_]+|DAT_([0-9a-fA-F]+))", args_str)
            if gm:
                g_ref = gm.group(1)
                if gm.group(2):
                    # Try RVA (assuming ImageBase might be 0 or 0x140000000; lower 24 bits if < len)
                    addr_val = int(gm.group(2), 16)
                    rva_guess = addr_val & 0xFFFFFF if addr_val >= 0x10000000 else addr_val
                    g_uuid = extract_guid_at_rva(efi_bytes, hex(rva_guess))
            proto_xrefs.append({
                "caller_rva": rva,
                "caller_name": suggested or f["name"],
                "service": op,
                "guid_ref": g_ref,
                "guid_uuid": g_uuid,
                "args_preview": args_str[:160],
            })

        enriched[rva] = {
            "original_name": f["name"],
            "suggested_name": suggested or f["name"],
            "size": f["size"],
            "file": f["file"],
            "source_files": src_files,
            "log_hints": sorted(set(log_hints)),
            "guids": f.get("guids", []),
            "strings": strs,
            "callers": f.get("callers", []),
            "callees": f.get("callees", []),
        }

    out = {
        "module_dir": str(decomp_dir),
        "summary": {
            "total_functions": len(funcs),
            "primitives_found": len(primitives),
            "source_files_found": sorted(by_source.keys()),
            "protocol_xref_count": len(proto_xrefs),
        },
        "primitives": primitives,
        "by_source_file": dict(sorted(by_source.items())),
        "protocol_xrefs": proto_xrefs,
        "functions": enriched,
    }
    (decomp_dir / "symbol_map.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[enrich] {decomp_dir.name}: funcs={len(funcs)}, primitives={len(primitives)}, proto_xrefs={len(proto_xrefs)}")


def main():
    if len(sys.argv) >= 3:
        enrich_module(Path(sys.argv[1]), Path(sys.argv[2]))
    else:
        for var in ("F", "N", "A9200"):
            for mod in ("LinuxLoader", "Odin"):
                ddir = WORKSPACE / "decomp" / f"{var}_{mod}"
                epath = WORKSPACE / "extracted" / var / f"{mod}.efi"
                if (ddir / "functions.json").exists():
                    enrich_module(ddir, epath)


if __name__ == "__main__":
    main()
