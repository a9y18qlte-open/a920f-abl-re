#!/usr/bin/env python3
"""Compare Samsung Galaxy A9 2018 (a9y18qlte, SDM660) ABL firmware across three
regional variants: SM-A920F (F), SM-A920N (N), and SM-A9200 (A9200).

Performs:
  1. ELF / MBN v5 / X.509 certificate / Samsung SignerVer02 / OuterFV & InnerFV comparison
  2. PE32+ section layout, JPEG payload array stride analysis, and non-JPEG string diffs
  3. Capstone-normalized function-level diff (plus uncovered .text gap diff) across
     LinuxLoader.efi and Odin.efi, distinguishing genuine code/logic changes from
     address-shift, __LINE__, and JPEG-stride constant differences.
"""

import argparse
import difflib
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

WORKSPACE = Path(__file__).resolve().parent.parent
VARIANTS = ("F", "N", "A9200")
MODULES = ("LinuxLoader", "Odin")


def load_metadata(variant: str) -> dict:
    return json.loads((WORKSPACE / "extracted" / variant / "elf_mbn_metadata.json").read_text())


def parse_leaf_cert_fields(abl_bytes: bytes) -> dict:
    """Extract X.509 leaf certificate subject OU fields and signature metadata."""
    seg1 = abl_bytes[0x1000:0x2988]
    m = re.search(b"\x30\x82..\x30\x82", seg1)
    if not m:
        return {}
    start = m.start()
    clen = struct.unpack_from(">H", seg1, start + 2)[0] + 4
    der = seg1[start : start + clen]
    txt = subprocess.check_output(
        ["openssl", "x509", "-inform", "DER", "-noout", "-text"], input=der
    ).decode("utf-8", "replace")
    ou_map = {}
    for code, hexval, label in re.findall(r"OU\s*=\s*(\d{2})\s+([0-9A-Fa-f]+)\s+([A-Z0-9_]+)", txt):
        ou_map[label] = {"id": code, "hex": hexval}
    sig_alg = re.search(r"Signature Algorithm:\s*(\S+)", txt)
    pub_bits = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", txt)
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "sig_alg": sig_alg.group(1) if sig_alg else None,
        "pub_bits": int(pub_bits.group(1)) if pub_bits else None,
        "ou": ou_map,
    }


def parse_signer_v2(abl_bytes: bytes) -> dict:
    """Parse 512-byte Samsung SignerVer02 trailer at end of abl.elf."""
    off = len(abl_bytes) - 0x200
    f = abl_bytes[off:]
    def cstr(s: int, e: int) -> str:
        return f[s:e].split(b"\x00", 1)[0].decode("ascii", "replace")

    return {
        "offset": hex(off),
        "magic": cstr(0x00, 0x10),
        "signer_id": cstr(0x10, 0x20),
        "build_id": cstr(0x20, 0x40),
        "build_time": cstr(0x40, 0x50),
        "project_id": cstr(0x50, 0x70),
        "qb_id_1": cstr(0x70, 0x80),
        "qb_id_2": cstr(0x80, 0x90),
        "binary_name": cstr(0xB0, 0xD0) or cstr(0x90, 0xE0),
        "tail_sig_sha256": hashlib.sha256(f[0x1E0:0x200]).hexdigest()[:16],
        "tail_hex_1e0_200": f[0x1E0:0x200].hex(),
    }


def compare_containers() -> dict:
    out = {}
    for v in VARIANTS:
        meta = load_metadata(v)
        abl = (WORKSPACE / "extracted" / v / "abl.elf").read_bytes()
        out[v] = {
            "abl_sha256": meta["total_sha256"],
            "abl_size": meta["total_size"],
            "seg2_pt_load_sha256": meta["segments"][2]["sha256"],
            "outer_fv_ffs_size": meta["outer_fv"]["files"][0]["size"],
            "outer_fv_decompressed_size": meta["outer_fv"]["files"][0]["sections"][0]["decompressed_size"],
            "inner_fv_length": meta["inner_fv"]["length"],
            "leaf_cert": parse_leaf_cert_fields(abl),
            "certs_summary": [
                {"serial": c["serial"], "notBefore": c["notBefore"], "notAfter": c["notAfter"], "sha256": c["sha256"]}
                for c in meta["mbn"]["certs"]
            ],
            "signer_v2": parse_signer_v2(abl),
            "modules": {
                m["ui_name"]: {
                    "ffs_size": m["ffs_size"],
                    "pe_size": m["pe"]["size"],
                    "pe_sha256": m["pe"]["sha256"],
                    "sections": m["pe"]["sections"],
                }
                for m in meta["inner_fv"]["modules"]
            },
        }
    return out


def scan_jpegs(efi_bytes: bytes) -> list[dict]:
    """Locate embedded JPEG streams (FF D8 FF ... FF D9) and parse SOF dimensions."""
    jpegs = []
    pos = 0
    while True:
        s = efi_bytes.find(b"\xff\xd8\xff", pos)
        if s == -1:
            break
        e = efi_bytes.find(b"\xff\xd9", s, s + 150000)
        end = (e + 2) if e != -1 else -1
        dims = None
        sof = re.search(b"\xff[\xc0\xc2]\x00[\x00-\xff]\x08(..)(..)", efi_bytes[s : s + 2048])
        if sof:
            h, w = struct.unpack(">HH", sof.group(1) + sof.group(2))
            dims = f"{w}x{h}"
        jpegs.append({
            "rva": hex(s),
            "size": (end - s) if end != -1 else None,
            "dims": dims,
        })
        pos = end if end != -1 else s + 3
    return jpegs


def mask_jpegs(efi_bytes: bytes) -> bytes:
    ba = bytearray(efi_bytes)
    pos = 0
    while True:
        s = efi_bytes.find(b"\xff\xd8\xff", pos)
        if s == -1:
            break
        e = efi_bytes.find(b"\xff\xd9", s, s + 150000)
        end = (e + 2) if e != -1 else min(len(efi_bytes), s + 100000)
        for k in range(s, end):
            ba[k] = 0
        pos = end
    return bytes(ba)


def compare_data_and_strings() -> dict:
    res = {}
    for mod in MODULES:
        jpegs = {}
        non_jpeg_strs = {}
        func_strs = {}
        for v in VARIANTS:
            b = (WORKSPACE / "extracted" / v / f"{mod}.efi").read_bytes()
            jpegs[v] = scan_jpegs(b)
            masked = mask_jpegs(b)
            non_jpeg_strs[v] = {
                m.decode("ascii", "ignore") for m in re.findall(rb"[ -~]{5,}", masked)
            }
            funcs = json.loads((WORKSPACE / "decomp" / f"{v}_{mod}" / "functions.json").read_text())
            func_strs[v] = {s for fn in funcs for s in fn.get("strings", [])}

        uniq_func_strs = {}
        uniq_raw_strs = {}
        for v in VARIANTS:
            others_f = set().union(*(func_strs[o] for o in VARIANTS if o != v))
            uniq_func_strs[v] = sorted(func_strs[v] - others_f)
            others_r = set().union(*(non_jpeg_strs[o] for o in VARIANTS if o != v))
            # Filter out short random-looking binary artifacts by keeping human-readable tokens
            uniq_raw_strs[v] = sorted(
                s for s in (non_jpeg_strs[v] - others_r)
                if len(s) >= 8 or any(k in s for k in ("SM-A920", "A920", "FRP", "PIT", "KOR", "CHN", "OPEN", "HK"))
            )

        strides = {}
        for v in VARIANTS:
            offs = [int(j["rva"], 16) for j in jpegs[v]]
            strides[v] = [hex(offs[i + 1] - offs[i]) for i in range(min(18, len(offs) - 1))]

        res[mod] = {
            "jpeg_counts": {v: len(jpegs[v]) for v in VARIANTS},
            "jpeg_first18_strides": strides,
            "jpegs": jpegs,
            "unique_function_strings": uniq_func_strs,
            "unique_filtered_raw_strings": uniq_raw_strs,
        }
    return res


def normalize_arm64_func(md: Cs, efi_bytes: bytes, rva: int, size: int) -> list[str]:
    """Normalize ARM64 instructions so PC-relative ADRP/ADD/LDR offsets and
    branch targets do not trigger false-positive diffs on relocated functions."""
    ins = list(md.disasm(efi_bytes[rva : rva + size], rva))
    out = []
    tainted = set()
    for i in ins:
        m, o = i.mnemonic, i.op_str
        if m == "adrp":
            r = o.split(",")[0].strip()
            tainted.add(r)
            out.append(f"adrp {r}, #P")
        elif m == "adr":
            r = o.split(",")[0].strip()
            tainted.add(r)
            out.append(f"adr {r}, #A")
        elif m in ("bl", "b") or m.startswith("b."):
            out.append(f"{m} #T")
        elif m in ("cbz", "cbnz", "tbz", "tbnz"):
            idx = o.rfind(",")
            prefix = o[:idx] if idx != -1 else o
            out.append(f"{m} {prefix}, #T")
        elif m == "add" and "#" in o:
            ps = [p.strip() for p in o.split(",")]
            if len(ps) == 3 and ps[1] in tainted:
                tainted.add(ps[0])
                out.append(f"add {ps[0]}, {ps[1]}, #L")
            else:
                if ps[0] in tainted:
                    tainted.discard(ps[0])
                out.append(f"{m} {o}")
        elif m.startswith(("ldr", "ldp", "str")) and "#" in o:
            m2 = re.search(r"\[([wx]\d+|sp),\s*#-?0x[0-9a-fA-F]+\]|\[([wx]\d+|sp),\s*#-?\d+\]", o)
            if m2 and (m2.group(1) or m2.group(2)) in tainted:
                br = m2.group(1) or m2.group(2)
                out.append(re.sub(r"\[([wx]\d+|sp),\s*#[^\]]+\]", f"[{br}, #L]", f"{m} {o}"))
            else:
                out.append(f"{m} {o}")
        else:
            dst = o.split(",")[0].strip() if o else ""
            if dst in tainted and not m.startswith("str"):
                tainted.discard(dst)
            out.append(f"{m} {o}")
    return out


def uncover_gaps(funcs: list[dict]) -> list[tuple[int, int]]:
    ordered = sorted(funcs, key=lambda x: int(x["rva"], 16))
    cur = 0x1000
    gaps = []
    for f in ordered:
        s = int(f["rva"], 16)
        if s > cur + 32:
            gaps.append((cur, s))
        cur = max(cur, s + f["size"])
    return gaps


def compare_functions() -> dict:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = {}
    for mod in MODULES:
        funcs = {
            v: json.loads((WORKSPACE / "decomp" / f"{v}_{mod}" / "functions.json").read_text())
            for v in VARIANTS
        }
        efis = {
            v: (WORKSPACE / "extracted" / v / f"{mod}.efi").read_bytes()
            for v in VARIANTS
        }
        hashes = {
            v: [
                hashlib.sha256(
                    "\n".join(normalize_arm64_func(md, efis[v], int(f["rva"], 16), f["size"])).encode()
                ).hexdigest()[:12]
                for f in funcs[v]
            ]
            for v in VARIANTS
        }

        pairs = {}
        for other in ("N", "A9200"):
            sm = difflib.SequenceMatcher(None, hashes["F"], hashes[other], autojunk=False)
            diffs = []
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == "equal":
                    continue
                diffs.append({
                    "op": tag,
                    "F": [
                        {"rva": funcs["F"][k]["rva"], "size": funcs["F"][k]["size"], "strings": funcs["F"][k]["strings"][:3]}
                        for k in range(i1, i2)
                    ],
                    other: [
                        {"rva": funcs[other][k]["rva"], "size": funcs[other][k]["size"], "strings": funcs[other][k]["strings"][:3]}
                        for k in range(j1, j2)
                    ],
                })

            # Also compare uncovered .text gaps (e.g. Odin 0x47b4..0x68c0 main command loop, AVB ops)
            g_f = uncover_gaps(funcs["F"])
            g_o = uncover_gaps(funcs[other])
            sig_f = [" ".join(i.mnemonic for i in md.disasm(efis["F"][s:e], s)) for s, e in g_f]
            sig_o = [" ".join(i.mnemonic for i in md.disasm(efis[other][s:e], s)) for s, e in g_o]
            sm_g = difflib.SequenceMatcher(None, sig_f, sig_o, autojunk=False)
            gap_diffs = []
            for tag, i1, i2, j1, j2 in sm_g.get_opcodes():
                if tag == "equal":
                    continue
                gap_diffs.append({
                    "op": tag,
                    "F": [{"start": hex(g_f[k][0]), "end": hex(g_f[k][1]), "size": g_f[k][1] - g_f[k][0]} for k in range(i1, i2)],
                    other: [{"start": hex(g_o[k][0]), "end": hex(g_o[k][1]), "size": g_o[k][1] - g_o[k][0]} for k in range(j1, j2)],
                })

            pairs[f"F_vs_{other}"] = {
                "function_diffs": diffs,
                "uncovered_gap_diffs": gap_diffs,
            }

        out[mod] = {
            "function_counts": {v: len(funcs[v]) for v in VARIANTS},
            "comparisons": pairs,
        }
    return out


def print_report(containers: dict, data_info: dict, func_info: dict) -> None:
    print("=" * 72)
    print("1. ELF / MBN v5 / X.509 / SignerVer02 / InnerFV SUMMARY")
    print("=" * 72)
    for v in VARIANTS:
        c = containers[v]
        sv2 = c["signer_v2"]
        ou = c["leaf_cert"]["ou"]
        print(f"[{v}] {sv2['build_id']} | proj={sv2['project_id']} | time={sv2['build_time']} | signer={sv2['signer_id']} | qb={sv2['qb_id_1']}")
        print(f"    abl.elf sha256={c['abl_sha256']}")
        print(f"    SW_ID={ou.get('SW_ID',{}).get('hex')} HW_ID={ou.get('HW_ID',{}).get('hex')} OEM_ID={ou.get('OEM_ID',{}).get('hex')} MODEL_ID={ou.get('MODEL_ID',{}).get('hex')}")
        print(f"    OuterFV ffs={c['outer_fv_ffs_size']} decomp={c['outer_fv_decompressed_size']} | InnerFV len={c['inner_fv_length']}")
        for mname, minfo in c["modules"].items():
            secs = ", ".join(f"{s['name']}@{s['vaddr']}+{s['raw_size']}" for s in minfo["sections"])
            print(f"    {mname:11s}: ffs={minfo['ffs_size']} pe={minfo['pe_size']} ({secs})")

    print("\n" + "=" * 72)
    print("2. .DATA JPEG PAYLOADS & UNIQUE STRINGS")
    print("=" * 72)
    for mod in MODULES:
        d = data_info[mod]
        print(f"[{mod}] JPEGs={d['jpeg_counts']}")
        for v in VARIANTS:
            print(f"  {v:5s} first 18 JPEG strides: {d['jpeg_first18_strides'][v]}")
            print(f"  {v:5s} unique func strings ({len(d['unique_function_strings'][v])}): {d['unique_function_strings'][v]}")
            print(f"  {v:5s} unique raw strings  ({len(d['unique_filtered_raw_strings'][v])}): {d['unique_filtered_raw_strings'][v]}")

    print("\n" + "=" * 72)
    print("3. FUNCTION & UNCOVERED-GAP DIFFS (CAPSTONE-NORMALIZED)")
    print("=" * 72)
    for mod in MODULES:
        fi = func_info[mod]
        print(f"[{mod}] function counts={fi['function_counts']}")
        for pair_name, pdata in fi["comparisons"].items():
            print(f"  --- {pair_name} ---")
            for item in pdata["function_diffs"]:
                f_str = [(x["rva"], x["size"], x["strings"][:2]) for x in item["F"]]
                other_key = [k for k in item if k not in ("op", "F")][0]
                o_str = [(x["rva"], x["size"], x["strings"][:2]) for x in item[other_key]]
                print(f"    {item['op']:7s} F={f_str} -> {other_key}={o_str}")
            if pdata["uncovered_gap_diffs"]:
                print(f"  --- {pair_name} uncovered .text gaps ---")
                for g in pdata["uncovered_gap_diffs"]:
                    other_key = [k for k in g if k not in ("op", "F")][0]
                    print(f"    {g['op']:7s} F={g['F']} -> {other_key}={g[other_key]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Diff SM-A920F / SM-A920N / SM-A9200 ABL variants")
    parser.add_argument("--json", type=Path, help="Optional path to dump full structured JSON output")
    args = parser.parse_args()

    containers = compare_containers()
    data_info = compare_data_and_strings()
    func_info = compare_functions()

    print_report(containers, data_info, func_info)

    if args.json:
        payload = {"containers": containers, "data": data_info, "functions": func_info}
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nWrote JSON report to {args.json}")


if __name__ == "__main__":
    main()
