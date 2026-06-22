import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;

// Seed disasm from the vector table (flash @0x80000) + known code sites, then let
// the analyzers fan out (analyzeChanges) so flow + operand references propagate.
// Then list refs into the 0xE694-0xE7D7 XRAM pool, flagging BOOT-sector sources.
public class XrefDeep extends GhidraScript {
    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long BASE = 0x80000L;
        for (long a = BASE; a < BASE + 0x600; a += 4) tryDis(sp, a);
        long[] seeds = {0x1FC84L,0x4B544L,0x4B5C6L,0x26A38L,0x43726L,0x092C0L,0x0B490L,
                        0xD0168L,0xD022AL,0xD0262L,0xD029AL,0xD0358L};
        for (long s : seeds) tryDis(sp, BASE + (s & 0x7FFFFL));
        analyzeChanges(currentProgram);   // let analyzers follow flow + build references

        ReferenceManager rm = currentProgram.getReferenceManager();
        Listing lst = currentProgram.getListing();
        long ins = 0;
        for (Instruction i : lst.getInstructions(true)) ins++;
        println("INSTRUCTIONS disassembled: " + ins);

        long LO = 0xE694L, HI = 0xE7D7L, BOOT_LO = 0x80000L, BOOT_HI = 0x8FFFFL;
        println(String.format("=== references into 0x%04X-0x%04X ===", LO, HI));
        int total = 0, writes = 0, bootRefs = 0, bootWrites = 0;
        AddressIterator it = rm.getReferenceDestinationIterator(sp.getAddress(LO), true);
        while (it.hasNext()) {
            Address dst = it.next(); long d = dst.getOffset();
            if (d > HI) break;
            if (d < LO) continue;
            for (Reference ref : rm.getReferencesTo(dst)) {
                Address src = ref.getFromAddress(); long s = src.getOffset();
                RefType rt = ref.getReferenceType();
                boolean isWrite = rt.isWrite();
                boolean inBoot = (s >= BOOT_LO && s <= BOOT_HI);
                Instruction insn = lst.getInstructionAt(src);
                String txt = (insn != null) ? insn.toString() : "(data)";
                total++; if (isWrite) writes++; if (inBoot) { bootRefs++; if (isWrite) bootWrites++; }
                println(String.format("  dst %04X <- src %06X %-6s %s%s",
                        d, s, rt.getName(), inBoot ? "[BOOT] " : "", txt));
            }
        }
        println(String.format("--- total refs %d | writes %d | BOOT refs %d (writes %d) ---",
                total, writes, bootRefs, bootWrites));
    }
    void tryDis(AddressSpace sp, long a){ try{ disassemble(sp.getAddress(a)); }catch(Exception e){} }
}
