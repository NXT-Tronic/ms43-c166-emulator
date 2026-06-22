import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;

public class RamMap extends GhidraScript {
    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        ReferenceManager rm = currentProgram.getReferenceManager();

        // total instructions (coverage sanity)
        long ins = 0;
        for (Instruction i : currentProgram.getListing().getInstructions(true)) ins++;
        println("INSTRUCTIONS disassembled: " + ins);

        long[][] ranges = {{0xC000L,0xDFFFL},{0xE000L,0xE7FFL},{0xE800L,0xEBFFL},{0xF600L,0xFDFFL}};
        for (long[] r : ranges) {
            int n = (int)(r[1]-r[0]+1);
            boolean[] used = new boolean[n];
            int refcount = 0;
            AddressIterator it = rm.getReferenceDestinationIterator(sp.getAddress(r[0]), true);
            while (it.hasNext()) {
                Address a = it.next();
                long off = a.getOffset();
                if (off > r[1]) break;
                if (off >= r[0]) { used[(int)(off-r[0])] = true; refcount++; }
            }
            println(String.format("=== RAM 0x%04X-0x%04X : %d referenced addrs ===", r[0], r[1], refcount));
            int runStart = -1; long freeTot = 0;
            for (int i = 0; i <= n; i++) {
                boolean u = (i < n) && used[i];
                if (!u && i < n) { if (runStart < 0) runStart = i; }
                else { if (runStart >= 0) { int len = i - runStart; freeTot += len;
                    if (len >= 12) println(String.format("   FREE 0x%04X-0x%04X  %d B", r[0]+runStart, r[0]+i-1, len));
                    runStart = -1; } }
            }
            println(String.format("   (total unreferenced in range: %d B)", freeTot));
        }
    }
}
