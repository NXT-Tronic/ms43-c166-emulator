import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

// Targeted disassembly dump: postScript args = <startAddrHex> [count]
public class DumpAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long startOff = Long.decode(args[0]);
        int count = args.length > 1 ? Integer.decode(args[1]) : 80;
        Address a = toAddr(startOff);
        println("=== DUMP @ " + a + " (" + count + " instrs) ===");
        for (int i = 0; i < count && a != null; i++) {
            Instruction in = getInstructionAt(a);
            if (in == null) { disassemble(a); in = getInstructionAt(a); }
            if (in == null) { println(a + "  <undisassembled>"); a = a.next(); continue; }
            StringBuilder bytes = new StringBuilder();
            try { for (byte bb : in.getBytes()) bytes.append(String.format("%02X", bb)); } catch (Exception e) {}
            println(String.format("%-10s %-18s %s", in.getAddress(), bytes, in.toString()));
            Address nx = in.getMaxAddress();
            a = (nx == null) ? a.next() : nx.next();
        }
        println("=== END ===");
    }
}
