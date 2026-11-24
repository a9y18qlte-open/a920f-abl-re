#!/usr/bin/env python3
"""Unpack SM-A920F xbl.elf (XBL_Loader/Ramdump ELF, Sec.te, inner DXE FV, all DXE PE32+
drivers, configs, bitmaps) and bksecapp.mbn (QSEE 32-bit ARM TrustZone applet),
and refresh extracted/uefi_guids.{json,tsv} with verified ABL/XBL GUID names."""

import gzip
import hashlib
import io
import json
import re
import struct
import subprocess
import uuid
from pathlib import Path

from elftools.elf.elffile import ELFFile

WORKSPACE = Path(__file__).resolve().parent.parent
EXTRACTED = WORKSPACE / "extracted"
XBL_OUT = EXTRACTED / "F_XBL"
BK_OUT = EXTRACTED / "F_BKSECAPP"

XBL_LZ4 = "/mnt/g-smb/fw3way/F/BL/xbl.elf.lz4"
BK_LZ4 = "/mnt/g-smb/fw3way/F/BL/bksecapp.mbn.lz4"

GZIP_GUID = uuid.UUID("1d301fe9-be79-4353-91c2-d23bc959ae0c").bytes_le
APRIORI_GUID = "fc510ee7-ffdc-11d4-bd41-0080c73c8881"

VERIFIED_GUID_OVERRIDES = {
    "77ed108d-8524-4b8b-9d2e-34987aecb9c1": "QcomScmProtocol",
    "a74862ce-680f-4fe1-a311-df41f4030391": "QcomQseecomProtocol",
    "4684800a-2755-4edc-b443-7f8ceb3239d3": "QcomPmicVersionProtocol",
    "55b1d734-c5e1-49db-9647-b16afb0e305b": "EfiHash2Protocol_Qcom",
    "f4e5c7d0-d239-47cb-aacd-7f66ef763238": "QcomSmemProtocol",
    "ad9aec18-7bf0-4809-9e96-3012309f3df7": "QcomTlmmProtocol",
    "fe2555be-d716-4686-b9d0-79db5921b70d": "EfiPartitionRecordProtocol",
    "6848de61-eb61-4def-9a8e-3817cbeb8f1c": "EfiPartitionTypeGuidProtocol",
    "5172ffb5-4253-7d51-c641-a701f973103c": "QcomRamPartitionProtocol",
    "f57f73ed-0afc-4723-9374-2cebc0198ef9": "QcomKernelModeSwitchProtocol",
    "d35dc019-3eab-4655-ba9a-734a8d8b9847": "QcomEmmcWpProtocol",
    "ae1cdd2b-b59a-413a-8dff-56d2fc63b7e0": "QcomStorageWpProtocol",
    "1e28a9ba-54b1-4a93-9b45-56c8b4daa55c": "QcomEmmcPonProtocol",
    "8b0d8671-f542-4ee8-a70c-95f5524ae117": "QcomUfsSsuProtocol",
    "8f644fa9-e850-4db1-9ce2-0b44698e8da4": "EfiFirmwareVolumeBlock2Protocol",
    "56ec3091-954c-11d2-8e3f-00a0c969723b": "EfiLoadFileProtocol",
    "a77b2472-e282-4e9f-a245-c2c0e27bbcc1": "EfiBlockIo2Protocol",
    "d9d9ce48-44b8-494f-8e3e-2a3b927dc6c1": "QcomUsbDeviceProtocol",
    "1c0cffce-fc8d-4e44-8c78-9c9e5b530d36": "QcomUsbInitEventGuid",
    "8e5eff91-21b6-47d3-af2b-c15a01e020ec": "QcomVerifiedBootProtocol",
    "6edc8a6d-2663-43cd-90ff-4621ffd10df5": "QcomChargerProtocol",
    "d68edce2-a314-457b-962a-1d99bbfcbbfb": "QcomNandPartiGuidProtocol",
    "09576e93-6d3f-11d2-8e39-00a0c969723b": "EfiFileSystemVolumeLabelId",
    "51aa59de-fdf2-4ea3-bc63-875fb7842ee9": "EfiHashAlgorithmSha256Guid",
    "2ae9d80f-3fb2-4095-b7b1-e93157b946b6": "EfiHashAlgorithmSha1OrSec2Guid",
}


def parse_x509_der(der_bytes):
    p = subprocess.Popen(
        ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-serial", "-dates"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = p.communicate(der_bytes)
    if p.returncode != 0:
        return {"error": err.decode("utf-8", "replace"), "len": len(der_bytes)}
    info = {"len": len(der_bytes), "sha256": hashlib.sha256(der_bytes).hexdigest()}
    for line in out.decode("utf-8", "replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
    return info


def parse_elf_mbn(raw_bytes):
    elf = ELFFile(io.BytesIO(raw_bytes))
    segments = []
    for i, seg in enumerate(elf.iter_segments()):
        h = seg.header
        segments.append({
            "index": i,
            "type": str(h.p_type),
            "offset": hex(h.p_offset),
            "vaddr": hex(h.p_vaddr),
            "paddr": hex(h.p_paddr),
            "filesz": hex(h.p_filesz),
            "memsz": hex(h.p_memsz),
            "flags": hex(h.p_flags),
            "sha256": hashlib.sha256(seg.data()).hexdigest() if h.p_filesz > 0 else None,
        })

    seg1_hdr = elf.get_segment(1).header
    seg1 = raw_bytes[seg1_hdr.p_offset : seg1_hdr.p_offset + seg1_hdr.p_filesz]
    mbn_words = struct.unpack_from("<10I", seg1, 0)
    mbn = {
        "segment_offset": hex(seg1_hdr.p_offset),
        "segment_size": hex(seg1_hdr.p_filesz),
        "header_words_hex": [hex(w) for w in mbn_words],
        "version": mbn_words[1],
        "code_size": hex(mbn_words[5]),
        "sig_size": hex(mbn_words[7]),
        "cert_chain_size": hex(mbn_words[9]),
        "certs": [],
    }
    pos = 0
    while True:
        m = re.search(b"\x30\x82..\x30\x82", seg1[pos:])
        if not m:
            break
        start = pos + m.start()
        clen = struct.unpack_from(">H", seg1, start + 2)[0] + 4
        if start + clen <= len(seg1):
            cinfo = parse_x509_der(seg1[start : start + clen])
            cinfo["offset_in_seg1"] = hex(start)
            mbn["certs"].append(cinfo)
            pos = start + clen
        else:
            pos = start + 2

    signer_info = None
    if len(raw_bytes) >= 0x200 and raw_bytes[-0x200:].startswith(b"SignerVer"):
        footer = raw_bytes[-0x200:]
        signer_info = {
            "offset": hex(len(raw_bytes) - 0x200),
            "size": 512,
            "magic": footer[0:16].split(b"\x00")[0].decode("ascii", "replace"),
            "signer_id": footer[16:32].split(b"\x00")[0].decode("ascii", "replace"),
            "build_id": footer[32:64].split(b"\x00")[0].decode("ascii", "replace"),
            "tail_strings": [s.decode("ascii", "replace") for s in re.findall(b"[ -~]{4,}", footer[64:])],
        }

    return {
        "elf_class": str(elf.header["e_ident"]["EI_CLASS"]),
        "elf_machine": str(elf.header["e_machine"]),
        "elf_entry": hex(elf.header["e_entry"]),
        "e_phoff": elf.header["e_phoff"],
        "e_phentsize": elf.header["e_phentsize"],
        "e_phnum": elf.header["e_phnum"],
        "total_size": len(raw_bytes),
        "total_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "segments": segments,
        "mbn": mbn,
        "samsung_signer_footer": signer_info,
    }


def walk_fv(fv_bytes):
    fv_len, sig, attr, hdr_len, csum, ext_off, rev = struct.unpack_from("<Q4sIHHHxB", fv_bytes, 32)
    if sig != b"_FVH":
        raise ValueError(f"Bad FV sig: {sig}")
    if ext_off:
        ext_sz, = struct.unpack_from("<I", fv_bytes, ext_off + 16)
        off = (ext_off + ext_sz + 7) & ~7
    else:
        off = hdr_len
    files = []
    while off + 24 <= fv_len:
        off = (off + 7) & ~7
        while off + 24 <= fv_len and fv_bytes[off : off + 24] == b"\xff" * 24:
            off += 8
        if off + 24 > fv_len:
            break
        f_guid = uuid.UUID(bytes_le=fv_bytes[off : off + 16])
        f_type = fv_bytes[off + 18]
        f_attr = fv_bytes[off + 19]
        if f_guid.bytes == b"\xff" * 16 and f_type == 0xFF:
            break
        f_size = int.from_bytes(fv_bytes[off + 20 : off + 23], "little")
        if f_size == 0xFFFFFF or f_size < 24:
            break
        sections = []
        if f_type != 0xF0:
            s_off = off + 24
            f_end = off + f_size
            while s_off + 4 <= f_end:
                s_off = (s_off + 3) & ~3
                if s_off + 4 > f_end:
                    break
                s_sz = int.from_bytes(fv_bytes[s_off : s_off + 3], "little")
                s_type = fv_bytes[s_off + 3]
                s_hdr = 4
                if s_sz == 0xFFFFFF:
                    s_sz, = struct.unpack_from("<I", fv_bytes, s_off + 4)
                    s_hdr = 8
                if s_sz < s_hdr or s_off + s_sz > f_end:
                    break
                sections.append({
                    "offset": s_off,
                    "type": s_type,
                    "size": s_sz,
                    "hdr_size": s_hdr,
                    "body": fv_bytes[s_off + s_hdr : s_off + s_sz],
                })
                s_off += s_sz
        files.append({
            "offset": off,
            "guid": str(f_guid),
            "type": f_type,
            "attr": f_attr,
            "size": f_size,
            "sections": sections,
        })
        off += f_size
    return fv_len, files


def parse_pe_summary(pe_bytes):
    pe_off = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    mach, nsec = struct.unpack_from("<HH", pe_bytes, pe_off + 4)
    opt_sz, = struct.unpack_from("<H", pe_bytes, pe_off + 20)
    ep, = struct.unpack_from("<I", pe_bytes, pe_off + 24 + 16)
    imgbase, = struct.unpack_from("<Q", pe_bytes, pe_off + 24 + 24)
    sec_tbl = pe_off + 24 + opt_sz
    secs = []
    for i in range(nsec):
        sn, vsz, va, rsz, roff = struct.unpack_from("<8sIIII", pe_bytes, sec_tbl + i * 40)
        secs.append({
            "name": sn.rstrip(b"\x00").decode("ascii", "replace"),
            "vaddr": hex(va),
            "vsize": hex(vsz),
            "raw_off": hex(roff),
            "raw_size": hex(rsz),
        })
    return {
        "machine": hex(mach),
        "image_base": hex(imgbase),
        "entry_point_rva": hex(ep),
        "size": len(pe_bytes),
        "sha256": hashlib.sha256(pe_bytes).hexdigest(),
        "sections": secs,
    }


def unpack_xbl():
    (XBL_OUT / "dxe").mkdir(parents=True, exist_ok=True)
    (XBL_OUT / "cfg").mkdir(parents=True, exist_ok=True)
    (XBL_OUT / "bmp").mkdir(parents=True, exist_ok=True)

    xbl_raw = subprocess.check_output(["lz4", "-dc", XBL_LZ4])
    (XBL_OUT / "xbl.elf").write_bytes(xbl_raw)
    meta = parse_elf_mbn(xbl_raw)

    # Create xbl_loader.elf with Seg 12 (0x9fc00000 UEFI FV) patched to PT_NULL
    seg12 = meta["segments"][12]
    assert seg12["vaddr"] == "0x9fc00000" and seg12["type"] == "PT_LOAD", f"Unexpected Seg 12: {seg12}"
    loader_buf = bytearray(xbl_raw)
    ph12_off = meta["e_phoff"] + 12 * meta["e_phentsize"]
    assert struct.unpack_from("<I", loader_buf, ph12_off)[0] == 1
    struct.pack_into("<I", loader_buf, ph12_off, 0)  # PT_NULL
    (XBL_OUT / "xbl_loader.elf").write_bytes(loader_buf)
    (XBL_OUT / "xbl_mbn_metadata.json").write_text(json.dumps(meta, indent=2))

    # Walk Outer FV (Seg 12 at 0x8d5a0, size 0x1b5800)
    fv_off = int(seg12["offset"], 16)
    fv_sz = int(seg12["filesz"], 16)
    fv = xbl_raw[fv_off : fv_off + fv_sz]
    _, outer_files = walk_fv(fv)

    inner_fv = None
    for f in outer_files:
        for sec in f["sections"]:
            if sec["type"] == 0x12 and sec["body"][:2] == b"VZ":
                (XBL_OUT / "Sec.te").write_bytes(sec["body"])
            elif sec["type"] == 0x19 and b"[Config]" in sec["body"]:
                (XBL_OUT / "cfg" / "uefiplat.cfg").write_bytes(sec["body"])
            elif sec["type"] == 0x02 and sec["body"][:16] == GZIP_GUID:
                doff, _ = struct.unpack_from("<HH", sec["body"], 16)
                dec = gzip.decompress(sec["body"][doff - sec["hdr_size"] :])
                fvh_idx = dec.find(b"_FVH")
                if fvh_idx >= 40:
                    inner_fv = dec[fvh_idx - 40 :]

    if inner_fv is None:
        raise RuntimeError("Failed to find inner DXE FV inside xbl.elf")
    (XBL_OUT / "inner_dxe_fv.bin").write_bytes(inner_fv)

    ifv_len, inner_files = walk_fv(inner_fv)
    manifest = []
    guid_to_name = {}
    apriori_bytes = None

    for f in inner_files:
        ui = None
        pe_bytes = None
        raw_bytes = None
        depex_bytes = None
        for sec in f["sections"]:
            if sec["type"] == 0x15:
                ui = sec["body"].decode("utf-16le", "ignore").rstrip("\x00")
            elif sec["type"] == 0x10:
                pe_bytes = sec["body"]
            elif sec["type"] == 0x19:
                raw_bytes = sec["body"]
            elif sec["type"] == 0x13:
                depex_bytes = sec["body"]

        if ui:
            guid_to_name[f["guid"].lower()] = ui

        entry = {
            "guid": f["guid"],
            "ui_name": ui,
            "ffs_type": hex(f["type"]),
            "ffs_offset": hex(f["offset"]),
            "ffs_size": hex(f["size"]),
            "depex_hex": depex_bytes.hex() if depex_bytes else None,
        }

        if pe_bytes is not None and ui:
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", ui)
            (XBL_OUT / "dxe" / f"{safe}.efi").write_bytes(pe_bytes)
            entry["file"] = f"dxe/{safe}.efi"
            entry["pe"] = parse_pe_summary(pe_bytes)
        elif raw_bytes is not None:
            if f["guid"].lower() == APRIORI_GUID:
                apriori_bytes = raw_bytes
                (XBL_OUT / "cfg" / "apriori.bin").write_bytes(raw_bytes)
                entry["file"] = "cfg/apriori.bin"
            elif ui and ui.lower().endswith(".bmp"):
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", ui)
                (XBL_OUT / "bmp" / safe).write_bytes(raw_bytes)
                entry["file"] = f"bmp/{safe}"
            elif ui:
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", ui)
                (XBL_OUT / "cfg" / safe).write_bytes(raw_bytes)
                entry["file"] = f"cfg/{safe}"

        manifest.append(entry)

    (XBL_OUT / "dxe_manifest.json").write_text(json.dumps(manifest, indent=2))

    if apriori_bytes:
        apriori_order = []
        for off in range(0, len(apriori_bytes) - 15, 16):
            g = str(uuid.UUID(bytes_le=apriori_bytes[off : off + 16])).lower()
            apriori_order.append({"index": off // 16, "guid": g, "ui_name": guid_to_name.get(g)})
        (XBL_OUT / "cfg" / "apriori_order.json").write_text(json.dumps(apriori_order, indent=2))

    dxe_cnt = sum(1 for m in manifest if "pe" in m)
    print(f"[XBL] Unpacked xbl.elf ({len(xbl_raw)} B): {dxe_cnt} PE32+ DXE drivers, {len(manifest)} total FFS entries")


def unpack_bksecapp():
    BK_OUT.mkdir(parents=True, exist_ok=True)
    bk_raw = subprocess.check_output(["lz4", "-dc", BK_LZ4])
    (BK_OUT / "bksecapp.elf").write_bytes(bk_raw)
    meta = parse_elf_mbn(bk_raw)

    elf = ELFFile(io.BytesIO(bk_raw))
    dyn_syms = []
    for sec in elf.iter_sections():
        if sec.header["sh_type"] in ("SHT_DYNSYM", "SHT_SYMTAB"):
            for sym in sec.iter_symbols():
                if sym.name:
                    dyn_syms.append({
                        "name": sym.name,
                        "value": hex(sym["st_value"]),
                        "size": sym["st_size"],
                        "type": sym["st_info"]["type"],
                    })
    meta["symbols"] = dyn_syms
    (BK_OUT / "bksecapp_mbn_metadata.json").write_text(json.dumps(meta, indent=2))
    print(f"[BKSECAPP] Unpacked bksecapp.elf ({len(bk_raw)} B): {len(meta['segments'])} segs, {len(meta['mbn']['certs'])} certs, {len(dyn_syms)} syms")


def refresh_uefi_guids():
    guids_path = EXTRACTED / "uefi_guids.json"
    records = json.loads(guids_path.read_text(encoding="utf-8"))
    by_guid = {r["guid"].lower(): r for r in records}

    ll_bytes = (EXTRACTED / "F" / "LinuxLoader.efi").read_bytes()
    odin_bytes = (EXTRACTED / "F" / "Odin.efi").read_bytes()

    for g_str, name in VERIFIED_GUID_OVERRIDES.items():
        g_low = g_str.lower()
        le_bytes = uuid.UUID(g_low).bytes_le
        in_ll = le_bytes in ll_bytes
        in_odin = le_bytes in odin_bytes
        by_guid[g_low] = {
            "guid": g_low,
            "name": name,
            "bytes_le_hex": le_bytes.hex(),
            "in_F_LinuxLoader": in_ll,
            "in_F_Odin": in_odin,
        }

    out_records = sorted(by_guid.values(), key=lambda r: r["name"])
    tsv_lines = ["# guid_hex_le\tguid_str\tname\tin_LinuxLoader\tin_Odin"]
    for r in out_records:
        tsv_lines.append(
            f"{r['bytes_le_hex']}\t{r['guid']}\t{r['name']}\t{int(r['in_F_LinuxLoader'])}\t{int(r['in_F_Odin'])}"
        )

    guids_path.write_text(json.dumps(out_records, indent=2), encoding="utf-8")
    (EXTRACTED / "uefi_guids.tsv").write_text("\n".join(tsv_lines) + "\n", encoding="utf-8")
    print(f"[GUIDs] Refreshed uefi_guids: {len(out_records)} entries")


def main():
    unpack_xbl()
    unpack_bksecapp()
    refresh_uefi_guids()


if __name__ == "__main__":
    main()
