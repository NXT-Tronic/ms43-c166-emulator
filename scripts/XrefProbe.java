import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

// Diagnostic: report load base / blocks / instruction count, then list refs into
// the 0xE694-0xE7D7 pool with read/write + source instruction. Run with -process
// against an already-analyzed project (no re-import).
public class XrefProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("imageBase = " + currentProgram.getImageBase());
        for (MemoryBlock b : currentProgram.getMemory().getBlocks())
            println(String.format("  block %-12s %s - %s", b.getName(), b.getStart(), b.getEnd()));

        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Listing lst = currentProgram.getListing();
        long ins = 0;
        for (Instruction i : lst.getInstructions(true)) ins++;
        println("INSTRUCTIONS disassembled: " + ins);

        long LO = 0xE694L, HI = 0xE7D7L;
        println(String.format("=== references into 0x%04X-0x%04X ===", LO, HI));
        int total = 0, writes = 0;
        AddressIterator it = rm.getReferenceDestinationIterator(sp.getAddress(LO), true);
        while (it.hasNext()) {
            Address dst = it.next();
            long d = dst.getOffset();
            if (d > HI) break;
            if (d < LO) continue;
            for (Reference ref : rm.getReferencesTo(dst)) {
                Address src = ref.getFromAddress();
                RefType rt = ref.getReferenceType();
                boolean isWrite = rt.isWrite();
                Instruction insn = lst.getInstructionAt(src);
                String txt = (insn != null) ? insn.toString() : "(data)";
                total++; if (isWrite) writes++;
                println(String.format("  dst %04X <- src %s  %-6s %s", d, src, rt.getName(), txt));
            }
        }
        println(String.format("--- total refs %d | writes %d ---", total, writes));
    }
}
