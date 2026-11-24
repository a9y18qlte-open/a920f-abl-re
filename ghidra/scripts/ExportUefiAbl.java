// Export UEFI-typed decompilation, GUID labels, callgraph, and string/GUID xrefs from AArch64 PE32+ ABL modules.
// Usage: -postScript ExportUefiAbl.java <outDir> <guidsTsvPath>
//@category ABL-RE
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExportUefiAbl extends GhidraScript {

    private static class GuidEntry {
        byte[] bytes;
        String guidStr;
        String name;
    }

    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private DataType createUefiTypes(DataTypeManager dtm, Map<String, DataType> outTypes) {
        CategoryPath cat = new CategoryPath("/UEFI");
        DataType voidPtr = PointerDataType.getPointer(VoidDataType.dataType, dtm);
        DataType uint32 = UnsignedIntegerDataType.dataType;
        DataType uint64 = UnsignedLongLongDataType.dataType;
        DataType uint16 = UnsignedShortDataType.dataType;
        DataType uint8 = UnsignedCharDataType.dataType;

        StructureDataType guidDt = new StructureDataType(cat, "EFI_GUID", 0x10, dtm);
        guidDt.replaceAtOffset(0x0, uint32, 4, "Data1", null);
        guidDt.replaceAtOffset(0x4, uint16, 2, "Data2", null);
        guidDt.replaceAtOffset(0x6, uint16, 2, "Data3", null);
        guidDt.replaceAtOffset(0x8, new ArrayDataType(uint8, 8, 1, dtm), 8, "Data4", null);
        DataType efiGuid = dtm.addDataType(guidDt, DataTypeConflictHandler.REPLACE_HANDLER);

        StructureDataType hdrDt = new StructureDataType(cat, "EFI_TABLE_HEADER", 0x18, dtm);
        hdrDt.replaceAtOffset(0x00, uint64, 8, "Signature", null);
        hdrDt.replaceAtOffset(0x08, uint32, 4, "Revision", null);
        hdrDt.replaceAtOffset(0x0c, uint32, 4, "HeaderSize", null);
        hdrDt.replaceAtOffset(0x10, uint32, 4, "CRC32", null);
        hdrDt.replaceAtOffset(0x14, uint32, 4, "Reserved", null);
        DataType efiHdr = dtm.addDataType(hdrDt, DataTypeConflictHandler.REPLACE_HANDLER);

        String[] bsNames = {
            "RaiseTPL", "RestoreTPL", "AllocatePages", "FreePages", "GetMemoryMap",
            "AllocatePool", "FreePool", "CreateEvent", "SetTimer", "WaitForEvent",
            "SignalEvent", "CloseEvent", "CheckEvent", "InstallProtocolInterface",
            "ReinstallProtocolInterface", "UninstallProtocolInterface", "HandleProtocol",
            "Reserved", "RegisterProtocolNotify", "LocateHandle", "LocateDevicePath",
            "InstallConfigurationTable", "LoadImage", "StartImage", "Exit",
            "UnloadImage", "ExitBootServices", "GetNextMonotonicCount", "Stall",
            "SetWatchdogTimer", "ConnectController", "DisconnectController",
            "OpenProtocol", "CloseProtocol", "OpenProtocolInformation",
            "ProtocolsPerHandle", "LocateHandleBuffer", "LocateProtocol",
            "InstallMultipleProtocolInterfaces", "UninstallMultipleProtocolInterfaces",
            "CalculateCrc32", "CopyMem", "SetMem", "CreateEventEx"
        };
        StructureDataType bsDt = new StructureDataType(cat, "EFI_BOOT_SERVICES", 0x18 + bsNames.length * 8, dtm);
        bsDt.replaceAtOffset(0x00, efiHdr, 0x18, "Hdr", null);
        for (int i = 0; i < bsNames.length; i++) {
            bsDt.replaceAtOffset(0x18 + i * 8, voidPtr, 8, bsNames[i], null);
        }
        DataType efiBs = dtm.addDataType(bsDt, DataTypeConflictHandler.REPLACE_HANDLER);

        String[] rtNames = {
            "GetTime", "SetTime", "GetWakeupTime", "SetWakeupTime",
            "SetVirtualAddressMap", "ConvertPointer", "GetVariable",
            "GetNextVariableName", "SetVariable", "GetNextHighMonotonicCount",
            "ResetSystem", "UpdateCapsule", "QueryCapsuleCapabilities", "QueryVariableInfo"
        };
        StructureDataType rtDt = new StructureDataType(cat, "EFI_RUNTIME_SERVICES", 0x18 + rtNames.length * 8, dtm);
        rtDt.replaceAtOffset(0x00, efiHdr, 0x18, "Hdr", null);
        for (int i = 0; i < rtNames.length; i++) {
            rtDt.replaceAtOffset(0x18 + i * 8, voidPtr, 8, rtNames[i], null);
        }
        DataType efiRt = dtm.addDataType(rtDt, DataTypeConflictHandler.REPLACE_HANDLER);

        StructureDataType stDt = new StructureDataType(cat, "EFI_SYSTEM_TABLE", 0x78, dtm);
        stDt.replaceAtOffset(0x00, efiHdr, 0x18, "Hdr", null);
        stDt.replaceAtOffset(0x18, voidPtr, 8, "FirmwareVendor", null);
        stDt.replaceAtOffset(0x20, uint32, 4, "FirmwareRevision", null);
        stDt.replaceAtOffset(0x28, voidPtr, 8, "ConsoleInHandle", null);
        stDt.replaceAtOffset(0x30, voidPtr, 8, "ConIn", null);
        stDt.replaceAtOffset(0x38, voidPtr, 8, "ConsoleOutHandle", null);
        stDt.replaceAtOffset(0x40, voidPtr, 8, "ConOut", null);
        stDt.replaceAtOffset(0x48, voidPtr, 8, "StandardErrorHandle", null);
        stDt.replaceAtOffset(0x50, voidPtr, 8, "StdErr", null);
        stDt.replaceAtOffset(0x58, PointerDataType.getPointer(efiRt, dtm), 8, "RuntimeServices", null);
        stDt.replaceAtOffset(0x60, PointerDataType.getPointer(efiBs, dtm), 8, "BootServices", null);
        stDt.replaceAtOffset(0x68, uint64, 8, "NumberOfTableEntries", null);
        stDt.replaceAtOffset(0x70, voidPtr, 8, "ConfigurationTable", null);
        DataType efiSt = dtm.addDataType(stDt, DataTypeConflictHandler.REPLACE_HANDLER);

        outTypes.put("EFI_GUID", efiGuid);
        outTypes.put("EFI_BOOT_SERVICES", efiBs);
        outTypes.put("EFI_RUNTIME_SERVICES", efiRt);
        outTypes.put("EFI_SYSTEM_TABLE", efiSt);
        outTypes.put("EFI_BOOT_SERVICES*", PointerDataType.getPointer(efiBs, dtm));
        outTypes.put("EFI_RUNTIME_SERVICES*", PointerDataType.getPointer(efiRt, dtm));
        outTypes.put("EFI_SYSTEM_TABLE*", PointerDataType.getPointer(efiSt, dtm));
        outTypes.put("EFI_HANDLE", voidPtr);
        return efiSt;
    }

    private List<GuidEntry> loadGuids(String tsvPath) throws Exception {
        List<GuidEntry> list = new ArrayList<>();
        if (tsvPath == null || tsvPath.isEmpty()) return list;
        File f = new File(tsvPath);
        if (!f.exists()) return list;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\t");
                if (parts.length < 3) continue;
                if (parts[0].length() != 32) continue;
                GuidEntry ge = new GuidEntry();
                ge.bytes = hexToBytes(parts[0]);
                ge.guidStr = parts[1];
                ge.name = parts[2].replaceAll("[^A-Za-z0-9_]", "_");
                list.add(ge);
            }
        }
        return list;
    }

    private static long safeRva(Address addr, Address imageBase) {
        if (addr == null || imageBase == null) return 0L;
        if (addr.getAddressSpace().equals(imageBase.getAddressSpace())) {
            return addr.subtract(imageBase);
        }
        return addr.getOffset();
    }

    private void labelGuids(List<GuidEntry> guids, DataType efiGuidDt) throws Exception {
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        SymbolTable symtab = currentProgram.getSymbolTable();
        Address imageBase = currentProgram.getImageBase();
        int labeled = 0;
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || block.isOverlay() || block.getSize() > 0x2000000L) continue;
            byte[] buf = new byte[(int) block.getSize()];
            block.getBytes(block.getStart(), buf);
            for (GuidEntry ge : guids) {
                byte[] pat = ge.bytes;
                for (int off = 0; off <= buf.length - 16; off += 4) {
                    boolean match = true;
                    for (int k = 0; k < 16; k++) {
                        if (buf[off + k] != pat[k]) {
                            match = false;
                            break;
                        }
                    }
                    if (!match) continue;
                    Address addr = block.getStart().add(off);
                    String symName = "gGuid_" + ge.name;
                    Symbol existing = symtab.getPrimarySymbol(addr);
                    if (existing == null || !existing.getName().startsWith("gGuid_")) {
                        if (symtab.getSymbols(symName).hasNext()) {
                            symName = symName + "_" + Long.toHexString(safeRva(addr, imageBase));
                        }
                        Symbol lbl = symtab.createLabel(addr, symName, SourceType.USER_DEFINED);
                        lbl.setPrimary();
                    }
                    try {
                        listing.clearCodeUnits(addr, addr.add(15), false);
                        listing.createData(addr, efiGuidDt);
                    } catch (Exception ignored) {}
                    labeled++;
                }
            }
        }
        println("Labeled " + labeled + " UEFI GUID occurrences in non-exec blocks");
    }

    private void applyEntryAndDetectGlobals(DecompInterface dec, Map<String, DataType> types, Address imageBase) throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        SymbolTable symtab = currentProgram.getSymbolTable();
        Function entry = null;
        for (Symbol s : symtab.getSymbols("entry")) {
            entry = fm.getFunctionAt(s.getAddress());
            if (entry != null) break;
        }
        if (entry == null) {
            entry = fm.getFunctionAt(imageBase.add(0x1000));
        }
        if (entry == null) return;

        DataType efiHandle = types.get("EFI_HANDLE");
        DataType efiStPtr = types.get("EFI_SYSTEM_TABLE*");
        DataType efiBsPtr = types.get("EFI_BOOT_SERVICES*");
        DataType efiRtPtr = types.get("EFI_RUNTIME_SERVICES*");
        DataType uint64 = UnsignedLongLongDataType.dataType;

        Set<Function> initFuncs = new LinkedHashSet<>();
        initFuncs.add(entry);
        for (Function c1 : entry.getCalledFunctions(monitor)) {
            initFuncs.add(c1);
            for (Function c2 : c1.getCalledFunctions(monitor)) {
                initFuncs.add(c2);
            }
        }

        // Apply (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) to entry & its library constructor candidates
        for (Function f : initFuncs) {
            try {
                List<Parameter> params = new ArrayList<>();
                params.add(new ParameterImpl("ImageHandle", efiHandle, currentProgram));
                params.add(new ParameterImpl("SystemTable", efiStPtr, currentProgram));
                f.updateFunction(null, new ReturnParameterImpl(uint64, currentProgram), params,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
            } catch (Exception ignored) {}
        }

        // Decompile initFuncs to discover global gST, gBS, gRT, gImageHandle pointers
        Pattern pBs = Pattern.compile("([A-Za-z0-9_]+)\\s*=\\s*SystemTable->BootServices\\s*;");
        Pattern pRt = Pattern.compile("([A-Za-z0-9_]+)\\s*=\\s*SystemTable->RuntimeServices\\s*;");
        Pattern pSt = Pattern.compile("([A-Za-z0-9_]+)\\s*=\\s*SystemTable\\s*;");
        Pattern pIh = Pattern.compile("([A-Za-z0-9_]+)\\s*=\\s*ImageHandle\\s*;");

        Map<Address, String> globalRoles = new LinkedHashMap<>();
        for (Function f : initFuncs) {
            DecompileResults res = dec.decompileFunction(f, 60, monitor);
            if (res == null || res.getDecompiledFunction() == null) continue;
            String code = res.getDecompiledFunction().getC();
            matchGlobal(code, pBs, "gBS", globalRoles);
            matchGlobal(code, pRt, "gRT", globalRoles);
            matchGlobal(code, pSt, "gST", globalRoles);
            matchGlobal(code, pIh, "gImageHandle", globalRoles);
        }

        for (Map.Entry<Address, String> e : globalRoles.entrySet()) {
            Address addr = e.getKey();
            String role = e.getValue();
            DataType dt = efiHandle;
            if (role.equals("gBS")) dt = efiBsPtr;
            else if (role.equals("gRT")) dt = efiRtPtr;
            else if (role.equals("gST")) dt = efiStPtr;
            try {
                symtab.createLabel(addr, role, SourceType.USER_DEFINED);
                listing.clearCodeUnits(addr, addr.add(7), false);
                listing.createData(addr, dt);
                println("Typed global " + role + " @ RVA 0x" + Long.toHexString(addr.subtract(imageBase)));
            } catch (Exception ex) {
                println("Could not type " + role + " @ " + addr + ": " + ex.getMessage());
            }
        }
    }

    private void matchGlobal(String code, Pattern pat, String role, Map<Address, String> out) {
        Matcher m = pat.matcher(code);
        while (m.find()) {
            String sym = m.group(1);
            int idx = sym.lastIndexOf("DAT_");
            if (idx < 0) continue;
            String hexAddr = sym.substring(idx + 4);
            try {
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(hexAddr);
                if (a != null && currentProgram.getMemory().contains(a)) {
                    out.putIfAbsent(a, role);
                }
            } catch (Exception ignored) {}
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: ExportUefiAbl.java <outDir> [guidsTsvPath]");
        }
        File outDir = new File(args[0]);
        File funcsDir = new File(outDir, "funcs");
        funcsDir.mkdirs();
        String guidsPath = args.length >= 2 ? args[1] : "";

        String execFmt = currentProgram.getExecutableFormat();
        boolean isPe = execFmt != null && execFmt.contains("Portable Executable");

        int tx = currentProgram.startTransaction("UEFI Typing & GUID Labeling");
        try {
            Map<String, DataType> uefiTypes = new HashMap<>();
            createUefiTypes(currentProgram.getDataTypeManager(), uefiTypes);
            List<GuidEntry> guids = loadGuids(guidsPath);
            labelGuids(guids, uefiTypes.get("EFI_GUID"));

            if (isPe) {
                DecompInterface preDec = new DecompInterface();
                DecompileOptions opts = new DecompileOptions();
                preDec.setOptions(opts);
                preDec.openProgram(currentProgram);
                applyEntryAndDetectGlobals(preDec, uefiTypes, currentProgram.getImageBase());
                preDec.dispose();
            }
        } finally {
            currentProgram.endTransaction(tx, true);
        }

        DecompInterface dec = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.setEliminateUnreachable(false);
        dec.setOptions(opts);
        dec.openProgram(currentProgram);

        Address imageBase = currentProgram.getImageBase();
        Listing listing = currentProgram.getListing();
        SymbolTable symtab = currentProgram.getSymbolTable();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        List<Function> allFuncs = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            allFuncs.add(f);
        }
        allFuncs.sort(Comparator.comparing(Function::getEntryPoint));

        File allCFile = new File(outDir, "all_decomp.c");
        File jsonFile = new File(outDir, "functions.json");
        int okCount = 0;

        try (PrintWriter allW = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(allCFile), StandardCharsets.UTF_8)));
             PrintWriter jsonW = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(jsonFile), StandardCharsets.UTF_8)))) {

            allW.println("// Program: " + currentProgram.getName() + " | ImageBase: 0x" + Long.toHexString(imageBase.getOffset()));
            jsonW.println("[");

            for (int idx = 0; idx < allFuncs.size(); idx++) {
                Function f = allFuncs.get(idx);
                long va = f.getEntryPoint().getOffset();
                long rva = safeRva(f.getEntryPoint(), imageBase);
                long size = f.getBody().getNumAddresses();
                String fname = f.getName(true);

                Set<String> callers = new TreeSet<>();
                for (Function cf : f.getCallingFunctions(monitor)) {
                    callers.add("0x" + Long.toHexString(safeRva(cf.getEntryPoint(), imageBase)));
                }
                Set<String> callees = new TreeSet<>();
                for (Function cf : f.getCalledFunctions(monitor)) {
                    callees.add("0x" + Long.toHexString(safeRva(cf.getEntryPoint(), imageBase)));
                }

                Set<String> strings = new LinkedHashSet<>();
                Set<String> guidRefs = new LinkedHashSet<>();
                InstructionIterator iit = listing.getInstructions(f.getBody(), true);
                while (iit.hasNext()) {
                    Instruction ins = iit.next();
                    for (Reference r : refMgr.getReferencesFrom(ins.getAddress())) {
                        Address to = r.getToAddress();
                        if (to == null) continue;
                        Symbol prim = symtab.getPrimarySymbol(to);
                        if (prim != null && prim.getName().startsWith("gGuid_")) {
                            guidRefs.add(prim.getName() + "@0x" + Long.toHexString(safeRva(to, imageBase)));
                        }
                        Data d = listing.getDataAt(to);
                        if (d != null && d.hasStringValue()) {
                            Object val = d.getValue();
                            if (val != null) {
                                strings.add(val.toString());
                            }
                        }
                    }
                }

                DecompileResults dr = dec.decompileFunction(f, 120, monitor);
                String cCode = null;
                if (dr != null && dr.getDecompiledFunction() != null) {
                    cCode = dr.getDecompiledFunction().getC();
                    okCount++;
                }

                String rvaHex = String.format("0x%x", rva);
                String safeName = fname.replaceAll("[^A-Za-z0-9_.]", "_");
                if (safeName.length() > 100) safeName = safeName.substring(0, 100);
                long fileTag = isPe ? rva : va;
                String relFile = String.format("funcs/%08x_%s.c", fileTag, safeName);

                String header = String.format("// === FUNC %s @ RVA %s (VA 0x%x, size 0x%x) ===", fname, rvaHex, va, size);
                allW.println(header);
                if (!strings.isEmpty()) {
                    allW.println("// Strings: " + String.join(" | ", strings));
                }
                if (!guidRefs.isEmpty()) {
                    allW.println("// GUIDs: " + String.join(", ", guidRefs));
                }
                if (cCode != null) {
                    allW.println(cCode);
                    try (PrintWriter fw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(outDir, relFile)), StandardCharsets.UTF_8))) {
                        fw.println(header);
                        fw.print(cCode);
                    }
                } else {
                    allW.println("// <decompilation failed>\n");
                }

                // Write JSON record
                StringBuilder jb = new StringBuilder();
                jb.append("  {\"name\": \"").append(jsonEscape(fname)).append("\", ");
                jb.append("\"rva\": \"").append(rvaHex).append("\", ");
                jb.append("\"va\": \"0x").append(Long.toHexString(va)).append("\", ");
                jb.append("\"size\": ").append(size).append(", ");
                jb.append("\"file\": \"").append(jsonEscape(relFile)).append("\", ");
                jb.append("\"callers\": [").append(joinJsonStrings(callers)).append("], ");
                jb.append("\"callees\": [").append(joinJsonStrings(callees)).append("], ");
                jb.append("\"guids\": [").append(joinJsonStrings(guidRefs)).append("], ");
                jb.append("\"strings\": [").append(joinJsonStrings(strings)).append("]}");
                if (idx + 1 < allFuncs.size()) jb.append(",");
                jsonW.println(jb.toString());
            }
            jsonW.println("]");
        } finally {
            dec.dispose();
        }
        println("Exported " + okCount + "/" + allFuncs.size() + " functions to " + outDir.getAbsolutePath());
    }

    private static String joinJsonStrings(Collection<String> items) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String s : items) {
            if (!first) sb.append(", ");
            first = false;
            sb.append("\"").append(jsonEscape(s)).append("\"");
        }
        return sb.toString();
    }
}
