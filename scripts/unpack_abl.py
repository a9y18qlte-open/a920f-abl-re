#!/usr/bin/env python3
"""Unpack SM-A920F / SM-A920N / SM-A9200 abl.elf images, parse MBN/X.509/SignerVer02 metadata,
and extract companion XBL UEFI DXE GUIDs & uefiplat.cfg into extracted/."""

import gzip
import hashlib
import io
import json
import lzma
import os
import re
import struct
import subprocess
import tarfile
import uuid
from pathlib import Path

from elftools.elf.elffile import ELFFile

WORKSPACE = Path(__file__).resolve().parent.parent
EXTRACTED = WORKSPACE / "extracted"

VARIANTS = {
    "F": {"type": "lz4", "path": "/mnt/g-smb/fw3way/F/BL/abl.elf.lz4"},
    "N": {"type": "lz4", "path": "/mnt/g-smb/fw3way/N/BL/abl.elf.lz4"},
    "A9200": {
        "type": "tar_lz4",
        "path": "/mnt/g-smb/fw3way/stage/BL_A9200ZHU5CZB1_CL20954136_QB107562819_REV00_user_low_ship_MULTI_CERT.tar.md5",
        "member": "abl.elf.lz4",
    },
}

LZMA_GUID = uuid.UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf").bytes_le
GZIP_GUID = uuid.UUID("1d301fe9-be79-4353-91c2-d23bc959ae0c").bytes_le

# Curated EDK2 + Qualcomm QcomPkg / QcomModulePkg UEFI GUIDs
KNOWN_UEFI_GUIDS = {
    "5b1b31a1-9562-11d2-8e3f-00a0c969723b": "EfiLoadedImageProtocol",
    "bc62157e-3e33-4fec-9920-2d3b36d750df": "EfiLoadedImageDevicePathProtocol",
    "09576e91-6d3f-11d2-8e39-00a0c969723b": "EfiDevicePathProtocol",
    "8b843e20-8132-4852-90cc-551a4e4a7f1c": "EfiDevicePathToTextProtocol",
    "964e5b21-6459-11d2-8e39-00a0c969723b": "EfiBlockIoProtocol",
    "a77b2472-e282-4e9f-a245-c2c0e27bbbc1": "EfiBlockIo2Protocol",
    "ce345171-ba0b-11d2-8e4f-00a0c969723b": "EfiDiskIoProtocol",
    "8cf2f62c-bc96-488c-a84f-ff80e76e248b": "EfiPartitionInfoProtocol",
    "964e5b22-6459-11d2-8e39-00a0c969723b": "EfiSimpleFileSystemProtocol",
    "09576e92-6d3f-11d2-8e39-00a0c969723b": "EfiFileInfoId",
    "387477c1-69c7-11d2-8e39-00a0c969723b": "EfiSimpleTextInProtocol",
    "dd9e7534-7762-4698-8c14-f58517a625aa": "EfiSimpleTextInputExProtocol",
    "387477c2-69c7-11d2-8e39-00a0c969723b": "EfiSimpleTextOutProtocol",
    "9042a9de-23dc-4a38-96fb-7aded080516a": "EfiGraphicsOutputProtocol",
    "3152bca5-eade-433d-862e-c01cdc291f44": "EfiRngProtocol",
    "da836f8d-217f-4ca0-99c2-1c4a1ca5d7dc": "EfiHash2Protocol",
    "c5b9c74a-6d72-4719-99ab-c59f199091eb": "EfiHash2ServiceBindingProtocol",
    "2b2f68d6-0cd2-44cf-8e8b-bba20b1b5b75": "EfiUsbIoProtocol",
    "32d2963a-fe5d-4f30-b633-6e5dc55803cc": "EfiUsbfnIoProtocol",
    "bb25cf6f-f1d4-11d2-9a0c-0090273fc1fd": "EfiSerialIoProtocol",
    "220e73b6-6bdb-4413-8405-b974b108619a": "EfiFirmwareVolume2Protocol",
    "d3b36f2c-d551-11d4-9a46-0090273fc14d": "EfiGraphicsConsoleControl",
    "8be4df61-93ca-11d2-aa0d-00e098032b8c": "EfiGlobalVariable",
    "e0ba9b98-dd90-44aa-99c8-3a6a9155068f": "QcomRuntimeDebugOrHob",
    "7739f24c-93d7-11d4-9a3a-0090273fc14d": "EfiHobListGuid",
    "5b446ed1-e30b-4faa-871a-3654eca36080": "EfiDxeServicesTableGuid",
    "8868e871-e4f1-11d3-bc22-0080c73c8881": "EfiAcpi20TableGuid",
    "eb9d2d30-2d88-11d3-9a16-0090273fc14d": "EfiAcpi10TableGuid",
    "f2fd1544-9794-4a2c-992e-e5bbcf20e394": "EfiSmbios3TableGuid",
    "eb9d2d31-2d88-11d3-9a16-0090273fc14d": "EfiSmbiosTableGuid",
    "7a34b5c4-b08d-441c-9188-46eb24d23c62": "EfiQcomSdccConfigProtocol",
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EfiPartTypeSystemPart",
    "024dee41-33e7-11d3-9d69-0008c781f39f": "EfiPartTypeLegacyMbr",
    "ee4e5898-3914-4259-9d6e-dc7bd79403cf": "LzmaCustomDecompressGuid",
    "1d301fe9-be79-4353-91c2-d23bc959ae0c": "QcomGzipSectionGuid",
    "882f8c2b-9646-435f-8de5-f208ff80c1bd": "QcomTokenSpaceGuid",
    "95a9a93e-a86e-4926-aaef-9918e772d987": "EfiEraseBlockProtocol",
    "951727db-4321-4c76-a06b-87a6a1929206": "EfiStorageSecurityCommandProtocol",
    "a022155a-4828-4535-a499-11f15240b91b": "QcomResetReasonProtocol",
    "8e5eff91-21b6-47d3-af2b-c15a01e020ec": "QcomVerifiedBootProtocol",
    "a74862ce-680f-4fe1-a311-df41f4030391": "QcomScmOrTzProtocol",
    "55b1d734-c5e1-49db-9647-b16afb0e305b": "QcomHashOrVbProtocol",
    "51aa59de-fdf2-4ea3-bc63-875fb7842ee9": "QcomSecurityHashProtocol",
    "2ae9d80f-3fb2-4095-b7b1-e93157b946b6": "QcomSecurity2Protocol",
    "77ed108d-8524-4b8b-9d2e-34987aecb9c1": "QcomSharedDxeProtocol_77ed",
    "157a5c45-21b2-43c5-ba7c-822fee5fe599": "QcomPlatformInfoProtocol",
    "b0760469-970c-487a-a4b5-28db7b45cef1": "QcomChipInfoProtocol",
    "4684800a-2755-4edc-b443-7f8ceb3239d3": "QcomAdcProtocol",
    "85c1f7d2-bce6-4f31-8f4d-d37e03d05eaa": "EfiMemCardInfoProtocol",
    "fe2555be-d716-4686-b9d0-79db5921b70d": "QcomEnvOrPartitionProtocol_fe25",
    "ae1cdd2b-b59a-413a-8dff-56d2fc63b7e0": "QcomUfsLunProtocol",
    "8b0d8671-f542-4ee8-a70c-95f5524ae117": "QcomUfsProtocol_8b0d",
    "d35dc019-3eab-4655-ba9a-734a8d8b9847": "QcomSdccProtocol",
    "1e28a9ba-54b1-4a93-9b45-56c8b4daa55c": "QcomSdccProtocol_1e28",
    "5172ffb5-4253-7d51-c641-a701f973103c": "QcomEnvProtocol",
    "f57f73ed-0afc-4723-9374-2cebc0198ef9": "QcomEnv2Protocol",
    "97044b58-fea4-4ad0-9d0b-e417d60f11a1": "QcomPmicPwrOnProtocol",
    "fcbedc3e-d2a6-4234-9be5-c5ea93d1f392": "QcomPmicRtcProtocol",
    "f4e5c7d0-d239-47cb-aacd-7f66ef763238": "QcomSmemOrUsbProtocol_f4e5",
    "6848de61-eb61-4def-9a8e-3817cbeb8f1c": "QcomUsbfnOrDeviceProtocol_6848",
    "2cc73155-a1f9-4c4b-88e2-caf9390e126a": "SamsungMuicProtocol",
    "3c7596fa-0058-4496-a648-6d14be4023b2": "SamsungChargerProtocol",
    "6c3dbb2c-4354-4f5a-9e2f-40658db24402": "SamsungNpaLdoProtocol",
    "aa2e776d-8c9c-4268-998a-8b0a13bf0501": "SamsungVibratorProtocol",
    "ad9aec18-7bf0-4809-9e96-3012309f3df7": "QcomI2cOrPmicGpioProtocol",
    "e9ca4775-8657-47fc-97e7-7ed65a084324": "EfiHiiFontProtocol",
    "0fd96974-23aa-4cdc-b9cb-98d17750322a": "EfiHiiStringProtocol",
    "31a6406a-6bdf-4e46-b2a2-ebaa89c40920": "EfiHiiImageProtocol",
    "ef9fc172-a1b2-4693-b327-6d32fc416042": "EfiHiiDatabaseProtocol",
    "587e72d7-cc50-4f79-8209-ca291fc1a10f": "EfiHiiConfigRoutingProtocol",
    "03c4e603-ac28-11d3-9a2d-0090273fc14d": "EfiDebugPortProtocol",
    "8f644fa9-e850-4db1-9ce2-0b44698e8da4": "EfiUlogOrHobGuid_8f64",
    "59d1c24f-50f1-401a-b101-f33e0daed443": "EfiStatusCodeRuntimeProtocol",
    "d2b2b828-0826-48a7-b3df-983c006024f0": "EfiReportStatusCodeProtocol",
    "05ad34ba-6f02-4214-952e-4da0398e2bb9": "EfiDxeServicesTableLibGuid",
    "335984bd-e805-409a-b8f8-d27ece5ff7a6": "EfiMemoryTypeInformationGuid",
    "9a4e9246-d553-11d5-87e2-00062945c3b9": "EfiPrintLibGuid",
    "4c8a2451-c207-405b-9694-99ea13251341": "EfiHiiFrameworkGuid",
    "56ec3091-954c-11d2-8e3f-00a0c969723b": "EfiLoadedImageDevicePathProtocol_Alt",
    "4ba1d05f-088e-483f-a97e-b19b9ccf59b0": "QcomSdccUfsGuid_4ba1",
    "4acf98f6-26fa-44d2-8132-282f2d19a4c5": "QcomSdccUfsGuid_4acf",
    "8598155f-34de-415c-8b55-843e3322d36f": "QcomSdccUfsGuid_8598",
    "d719b2cb-3d3a-4596-a3bc-dad00e67656f": "EfiPartitionTypeUserData",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "EfiPartitionTypeBasicData",
    "c7f6b7d4-1e98-4b75-91f2-1827d03f14a5": "QcomBootModeGuid",
    "a83f3e60-c54e-4b3b-8e2d-d49635061501": "QcomTokenSpaceGuid",
    "8e5eff91-21b6-47d3-af2b-c15a01e020ec": "QcomTokenSpaceGuid_CAF",
    "eb704011-1402-11d3-8e77-00a0c969723b": "EfiCpuArchProtocol",
    "f541796d-a62e-4954-a775-9584f61b9c54": "EfiUsbDeviceProtocol",
    "d3c6eb21-77a9-4a62-bfaa-7d8c22923899": "EfiSdMmcPassThruProtocol",
    "0b913f6e-5862-4e77-8394-11df08a665f5": "EfiPartitionRecordGuid",
    "556d3e76-0d7b-48ea-89f9-7a0eb286796d": "QcomUfsBootLun",
    "24b09ebe-58a8-4f63-bfeb-30c8c338b96b": "QcomAdcProtocol",
    "529d3f93-e8e9-4e73-b1e1-bdf6a9d50113": "QcomUsbfnChgSrvProtocol",
    "4e2e30a4-52d7-4f86-93bf-7f95c5b821df": "QcomPmicGpioProtocol",
    "c4d35e5a-d07a-4483-b42d-a6bfeb047b19": "QcomPmicWledProtocol",
    "04c2c1c2-9f4e-4636-8d47-2478cf9c367c": "QcomPmicLpgProtocol",
    "6e73a0c0-25bf-4fa2-a816-fb4a5dc8b5e8": "QcomPmicRgbLedProtocol",
    "a60e2a4a-56d3-4f88-8b2f-2a49c9648e6f": "QcomTlmmProtocol",
    "1b1f62b5-63a1-43c3-b596-2a19d56139c4": "QcomMmuProtocol",
    "83360384-6b2c-414b-8290-bb9e48db7901": "QcomUefiVarProtocol",
    "f4321a6e-c9d8-4a1f-b7a2-7c976b74b8c9": "QcomDisplayPwrCtrlProtocol",
    "b811d2a7-4232-47ef-a393-08f5db2b5a82": "QcomUefiSecAppProtocol",
    "aba3b456-5469-414a-9f79-47cecbd7c04e": "SamsungOdinAppGuid",
    "f536d559-459f-48fa-8bbc-43b554ecae8d": "SamsungLinuxLoaderAppGuid",
    "9e21fd93-9c72-4c15-8c4b-e77f1db2d792": "AblCompressedFvGuid",
    "8c8ce578-8a3d-4f1c-9935-896185c32dd3": "EfiFirmwareFileSystem2Guid",
}


def load_lz4_source(spec):
    if spec["type"] == "lz4":
        return subprocess.check_output(["lz4", "-dc", spec["path"]])
    elif spec["type"] == "tar_lz4":
        with tarfile.open(spec["path"], "r:") as tf:
            for m in tf.getmembers():
                if m.name == spec["member"] or m.name.endswith("/" + spec["member"]):
                    comp = tf.extractfile(m).read()
                    p = subprocess.Popen(["lz4", "-dc"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    out, err = p.communicate(comp)
                    if p.returncode != 0:
                        raise RuntimeError(f"lz4 failed on {spec['member']}: {err}")
                    return out
    raise ValueError(f"Unknown spec type {spec}")


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


def extract_mbn_and_certs(raw_elf):
    elf = ELFFile(io.BytesIO(raw_elf))
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
            "sha256": hashlib.sha256(seg.data()).hexdigest(),
        })

    # Parse Seg 1 (MBN v5 hash segment at 0x1000)
    seg1_hdr = elf.get_segment(1).header
    seg1 = raw_elf[seg1_hdr.p_offset : seg1_hdr.p_offset + seg1_hdr.p_filesz]
    mbn_words = struct.unpack_from("<10I", seg1, 0)
    # QTI MBN v5 header layout: image_id(0), version(4), common_meta_sz(8)? / code_size etc.
    # Let's dump raw header fields + detect exact DER X.509 certificates
    mbn = {
        "segment_offset": hex(seg1_hdr.p_offset),
        "segment_size": hex(seg1_hdr.p_filesz),
        "header_words_hex": [hex(w) for w in mbn_words],
        "version": mbn_words[1],
        "code_size": hex(mbn_words[5]),
        "sig_size": hex(mbn_words[7]),
        "cert_chain_size": hex(mbn_words[9]),
        "segment_hashes_sha256": [],
        "certs": [],
    }
    hash_table_off = 0x28
    code_size = mbn_words[5]
    for h_off in range(hash_table_off, hash_table_off + code_size, 32):
        mbn["segment_hashes_sha256"].append(seg1[h_off : h_off + 32].hex())

    # Scan DER X.509 certs (SEQUENCE 30 82 len, TBSCertificate 30 82)
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

    # Samsung SignerVer02 footer at end of abl.elf (0x203000..0x203200)
    footer_off = len(raw_elf) - 0x200
    footer = raw_elf[footer_off:]
    signer_info = {"offset": hex(footer_off), "size": len(footer)}
    if footer.startswith(b"SignerVer"):
        signer_info["magic"] = footer[0:16].split(b"\x00")[0].decode("ascii", "replace")
        signer_info["signer_id"] = footer[16:32].split(b"\x00")[0].decode("ascii", "replace")
        signer_info["build_id"] = footer[32:64].split(b"\x00")[0].decode("ascii", "replace")
        signer_info["tail_strings"] = [
            s.decode("ascii", "replace") for s in re.findall(b"[ -~]{4,}", footer[64:])
        ]
        signer_info["raw_hex_00_80"] = footer[:0x80].hex()
    return {
        "elf_machine": str(elf.header["e_machine"]),
        "elf_class": str(elf.header["e_ident"]["EI_CLASS"]),
        "elf_entry": hex(elf.header["e_entry"]),
        "total_size": len(raw_elf),
        "total_sha256": hashlib.sha256(raw_elf).hexdigest(),
        "segments": segments,
        "mbn": mbn,
        "samsung_signer_footer": signer_info,
    }


def walk_fv(fv_bytes):
    """Walk UEFI Firmware Volume and yield dicts for each FFS file and its sections."""
    fv_len, sig, attr, hdr_len, csum, ext_off, rev = struct.unpack_from("<Q4sIHHHxB", fv_bytes, 32)
    if sig != b"_FVH":
        raise ValueError(f"Bad FV signature: {sig}")
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


def parse_pe32_info(pe_bytes):
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


def unpack_variant(variant, spec):
    out_dir = EXTRACTED / variant
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = load_lz4_source(spec)
    (out_dir / "abl.elf").write_bytes(raw)
    meta = extract_mbn_and_certs(raw)

    # Outer FV0 starts at ELF Seg 2 (0x3000), length 0x200000
    fv0 = raw[0x3000 : 0x3000 + 0x200000]
    fv0_len, outer_files = walk_fv(fv0)
    meta["outer_fv"] = {"offset": "0x3000", "length": hex(fv0_len), "files": []}

    inner_fv_bytes = None
    for f in outer_files:
        f_rec = {"guid": f["guid"], "type": hex(f["type"]), "size": hex(f["size"]), "sections": []}
        for sec in f["sections"]:
            s_rec = {"type": hex(sec["type"]), "size": hex(sec["size"])}
            if sec["type"] == 0x02 and sec["body"][:16] == LZMA_GUID:
                doff, attr = struct.unpack_from("<HH", sec["body"], 16)
                payload = sec["body"][doff - sec["hdr_size"] :]
                dec = lzma.decompress(payload)
                s_rec["compression"] = "LZMA"
                s_rec["decompressed_size"] = len(dec)
                fvh_idx = dec.find(b"_FVH")
                if fvh_idx >= 40:
                    inner_fv_bytes = dec[fvh_idx - 40 :]
            f_rec["sections"].append(s_rec)
        meta["outer_fv"]["files"].append(f_rec)

    if inner_fv_bytes is None:
        raise RuntimeError(f"Failed to locate inner FV in {variant}")
    (out_dir / "inner_fv.bin").write_bytes(inner_fv_bytes)

    ifv_len, inner_files = walk_fv(inner_fv_bytes)
    meta["inner_fv"] = {"length": hex(ifv_len), "modules": []}
    for f in inner_files:
        ui_name = None
        pe_bytes = None
        for sec in f["sections"]:
            if sec["type"] == 0x15:
                ui_name = sec["body"].decode("utf-16le", "ignore").rstrip("\x00")
            elif sec["type"] == 0x10:
                pe_bytes = sec["body"]
        mod_rec = {"guid": f["guid"], "ui_name": ui_name, "type": hex(f["type"]), "ffs_size": hex(f["size"])}
        if pe_bytes is not None and ui_name:
            efi_path = out_dir / f"{ui_name}.efi"
            efi_path.write_bytes(pe_bytes)
            mod_rec["pe"] = parse_pe32_info(pe_bytes)
        meta["inner_fv"]["modules"].append(mod_rec)

    (out_dir / "elf_mbn_metadata.json").write_text(json.dumps(meta, indent=2))
    print(f"[{variant}] Unpacked abl.elf ({len(raw)} B) -> modules={[m['ui_name'] for m in meta['inner_fv']['modules']]}")
    return meta


def unpack_xbl_info():
    xbl = subprocess.check_output(["lz4", "-dc", "/mnt/g-smb/fw3way/F/BL/xbl.elf.lz4"])
    fv = xbl[0x8D5A0 : 0x8D5A0 + 0x1B5800]
    _, files = walk_fv(fv)
    xbl_modules = []
    uefiplat_bytes = None

    for f in files:
        for sec in f["sections"]:
            if sec["type"] == 0x19 and b"uefiplat" in sec["body"]:
                uefiplat_bytes = sec["body"]
            elif sec["type"] == 0x02 and sec["body"][:16] == GZIP_GUID:
                doff, _ = struct.unpack_from("<HH", sec["body"], 16)
                dec = gzip.decompress(sec["body"][doff - sec["hdr_size"] :])
                # Find all _FVH inside dec
                pos = 0
                while True:
                    idx = dec.find(b"_FVH", pos)
                    if idx < 40:
                        if idx == -1:
                            break
                        pos = idx + 4
                        continue
                    sub_fv = dec[idx - 40 :]
                    sub_len, sub_files = walk_fv(sub_fv)
                    for sf in sub_files:
                        ui = None
                        for ss in sf["sections"]:
                            if ss["type"] == 0x15:
                                ui = ss["body"].decode("utf-16le", "ignore").rstrip("\x00")
                            elif ss["type"] == 0x19 and b"[ConfigParameters]" in ss["body"]:
                                uefiplat_bytes = ss["body"]
                        xbl_modules.append({"guid": sf["guid"], "ui_name": ui, "type": hex(sf["type"])})
                    pos = idx + 4

    if uefiplat_bytes:
        (EXTRACTED / "xbl_uefiplat.cfg").write_text(uefiplat_bytes.decode("utf-8", "replace"))
    (EXTRACTED / "xbl_dxe_modules.json").write_text(json.dumps(xbl_modules, indent=2))
    print(f"[XBL] Extracted {len(xbl_modules)} DXE/FV modules, uefiplat={'yes' if uefiplat_bytes else 'no'}")
    return xbl_modules


def build_guid_db(xbl_modules):
    guids = dict(KNOWN_UEFI_GUIDS)
    for m in xbl_modules:
        g = m["guid"].lower()
        if g not in guids and m.get("ui_name"):
            name = "XblDxe_" + re.sub(r"[^A-Za-z0-9_]", "_", m["ui_name"])
            guids[g] = name

    # Also check which known GUIDs actually appear in F/LinuxLoader.efi or F/Odin.efi
    ll_bytes = (EXTRACTED / "F" / "LinuxLoader.efi").read_bytes()
    odin_bytes = (EXTRACTED / "F" / "Odin.efi").read_bytes()

    records = []
    tsv_lines = ["# guid_hex_le\tguid_str\tname\tin_LinuxLoader\tin_Odin"]
    for g_str, name in sorted(guids.items(), key=lambda kv: kv[1]):
        le_bytes = uuid.UUID(g_str).bytes_le
        in_ll = le_bytes in ll_bytes
        in_odin = le_bytes in odin_bytes
        records.append({
            "guid": g_str,
            "name": name,
            "bytes_le_hex": le_bytes.hex(),
            "in_F_LinuxLoader": in_ll,
            "in_F_Odin": in_odin,
        })
        tsv_lines.append(f"{le_bytes.hex()}\t{g_str}\t{name}\t{int(in_ll)}\t{int(in_odin)}")

    (EXTRACTED / "uefi_guids.json").write_text(json.dumps(records, indent=2))
    (EXTRACTED / "uefi_guids.tsv").write_text("\n".join(tsv_lines) + "\n")
    hits_ll = sum(1 for r in records if r["in_F_LinuxLoader"])
    hits_od = sum(1 for r in records if r["in_F_Odin"])
    print(f"[GUIDs] Wrote {len(records)} entries (hits in F/LinuxLoader={hits_ll}, F/Odin={hits_od})")


def main():
    EXTRACTED.mkdir(parents=True, exist_ok=True)
    for v, spec in VARIANTS.items():
        unpack_variant(v, spec)
    xbl_modules = unpack_xbl_info()
    build_guid_db(xbl_modules)


if __name__ == "__main__":
    main()
