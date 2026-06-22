import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.Varnode;
import java.math.BigInteger;
import java.util.*;

// Iteration 2 (FAITHFUL): emulate MS43 boot with C166 addressing resolved from LIVE
// DPP + LIVE registers, so writes into the 0xE694-0xE7D7 pool are traced at their real
// runtime physical address (unlike the module's static-baked injector pcode).
// Implements CALLOTHER ops push/pop/segment/GetPagedOffset/c166_reg_offset_addr with
// correct C166 semantics; no-ops system ops; logs addressing-callback firings so we can
// tell whether the injector pre-empts us (if these never fire, we must disable it).
public class EmuBootF extends GhidraScript {
    static final long LO = 0xE694L, HI = 0xE7D7L; final int RN = (int)(HI-LO+1);
    EmulatorHelper emu;
    AddressSpace REG, RAM, CONST;
    long curPC = 0; int curLen = 2;
    int addrCalcFires = 0, poolAccessLogs = 0;
    static final long IP_REG_OFF = 0x20L;   // IP is the 17th word reg (r0..r15 then IP) at reg offset 0x20

    long rd(MemoryState ms, Varnode v) {
        if (v.isConstant()) return v.getOffset();
        return ms.getValue(v.getAddress().getAddressSpace(), v.getOffset(), v.getSize());
    }
    void wr(MemoryState ms, Varnode v, long val) {
        ms.setValue(v.getAddress().getAddressSpace(), v.getOffset(), v.getSize(), val);
    }
    long dpp(MemoryState ms, int n) { return ms.getValue(REG, 0xFE00L + 2L*n, 2) & 0x3FFL; }
    // hardware system stack pointer = SP SFR at ram 0xFE12 (NOT r0; r0 is the compiler user stack)
    long sp(MemoryState ms)          { return ms.getValue(RAM, 0xFE12L, 2) & 0xFFFFL; }
    void setSp(MemoryState ms, long v){ ms.setValue(RAM, 0xFE12L, 2, v & 0xFFFFL); }

    // resolve a 16-bit logical data address through the live DPP register (non-EXT path)
    long page(MemoryState ms, long logical) {
        logical &= 0xFFFF;
        long pg = dpp(ms, (int)((logical >> 14) & 3));
        long phys = (pg << 14) | (logical & 0x3FFF);
        if (phys >= LO && phys <= HI && poolAccessLogs < 200) {
            println(String.format("  ADDR-CALC -> pool %04X (logical %04X, DPP%d=%X) @PC %06X",
                    phys, logical, (int)((logical>>14)&3), pg, curPC));
            poolAccessLogs++;
        }
        return phys;
    }

    abstract class Op extends BreakCallBack {
        public boolean pcodeCallback(PcodeOpRaw op) { handle(getMemoryState(), op); return true; }
        MemoryState getMemoryState() { return emulate.getMemoryState(); }
        abstract void handle(MemoryState ms, PcodeOpRaw op);
    }

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        emu = new EmulatorHelper(currentProgram);
        REG  = emu.getLanguage().getAddressFactory().getRegisterSpace();
        RAM  = emu.getLanguage().getAddressFactory().getDefaultAddressSpace();
        CONST= emu.getLanguage().getAddressFactory().getConstantSpace();

        emu.setMemoryFaultHandler(new MemoryFaultHandler() {
            public boolean uninitializedRead(Address a, int size, byte[] buf, int off) { return true; }
            public boolean unknownAddress(Address a, boolean write) { return true; }
        });

        // ---- CALLOTHER implementations (live-register faithful) ----
        // GetPagedOffset(mem) -> live DPP-paged physical address
        emu.registerCallOtherCallback("GetPagedOffset", new Op() {
            void handle(MemoryState ms, PcodeOpRaw op) {
                addrCalcFires++;
                long mem = rd(ms, op.getInput(1)) & 0xFFFF;
                wr(ms, op.getOutput(), page(ms, mem));
            }});
        // c166_reg_offset_addr(reg, imm) -> live (reg+imm) DPP-paged
        emu.registerCallOtherCallback("c166_reg_offset_addr", new Op() {
            void handle(MemoryState ms, PcodeOpRaw op) {
                addrCalcFires++;
                long reg = rd(ms, op.getInput(1)) & 0xFFFF;
                long imm = rd(ms, op.getInput(2)) & 0xFFFF;
                wr(ms, op.getOutput(), page(ms, (reg + imm) & 0xFFFF));
            }});
        // segment(seg, off) -> (seg<<16)|off
        emu.registerCallOtherCallback("segment", new Op() {
            void handle(MemoryState ms, PcodeOpRaw op) {
                long seg = rd(ms, op.getInput(1)) & 0xFF;
                long off = rd(ms, op.getInput(2)) & 0xFFFF;
                wr(ms, op.getOutput(), (seg << 16) | off);
            }});
        // push(a): SP -= 2; mem[SP] = a   (system stack, grows negative; SP = SFR 0xFE12)
        // For push(IP) (the call return-address save) IP is a scratch reg here, not inst_next,
        // so substitute the true return address = curPC + instruction length.
        emu.registerCallOtherCallback("push", new Op() {
            void handle(MemoryState ms, PcodeOpRaw op) {
                Varnode in = op.getInput(1);
                long val;
                if (in.getAddress().getAddressSpace().equals(REG) && in.getOffset()==IP_REG_OFF && in.getSize()==2)
                    val = (curPC + curLen) & 0xFFFF;     // return address
                else
                    val = rd(ms, in);
                long s = (sp(ms) - 2) & 0xFFFF; setSp(ms, s);
                ms.setValue(RAM, s, 2, val & 0xFFFF);
            }});
        // pop(dst): dst = mem[SP]; SP += 2
        emu.registerCallOtherCallback("pop", new Op() {
            void handle(MemoryState ms, PcodeOpRaw op) {
                long s = sp(ms);
                long val = ms.getValue(RAM, s, 2) & 0xFFFF;
                wr(ms, op.getInput(1), val);
                setSp(ms, (s + 2) & 0xFFFF);
            }});
        // anything else (system ops: __nop, __disable_watchdog, __end_of_init, __idle, ...) -> no-op
        emu.registerDefaultCallOtherCallback(new Op() {
            HashSet<String> seenNames = new HashSet<>();
            void handle(MemoryState ms, PcodeOpRaw op) { /* no-op */ }
        });

        // mirror low flash window (seg 0) so reset code resolves
        byte[] low = new byte[0xE000];
        currentProgram.getMemory().getBytes(sp.getAddress(0x80000L), low);
        emu.writeMemory(sp.getAddress(0L), low);

        // C166 reset register state
        emu.writeRegister("DPP0", 0); emu.writeRegister("DPP1", 1);
        emu.writeRegister("DPP2", 2); emu.writeRegister("DPP3", 3);
        emu.writeMemory(sp.getAddress(0xFE12L), new byte[]{(byte)0x9C,(byte)0xF8}); // SP SFR=0xF89C (boot also sets it @0x2D94)
        try { emu.writeRegister("CSP", 0); } catch (Throwable t) {}
        emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(0x2D06L));
        println("start PC = " + emu.getExecutionAddress());

        byte[] prev = emu.readMemory(sp.getAddress(LO), RN);

        int MAX = 200000;
        HashMap<Long,Integer> seen = new HashMap<>();
        long lastPC = -1; int stuck = 0; String stop = "step cap"; int writeHits = 0;
        long[] jmpFrom = new long[40], jmpTo = new long[40]; int ji = 0; int jmpCount = 0;
        long maxPC = 0, minPC = 0xFFFFFFFFL;
        for (int s = 0; s < MAX; s++) {
            try { curPC = emu.getExecutionAddress().getOffset(); }
            catch (Throwable t) { stop = "no PC: " + t; break; }
            if (curPC > maxPC) maxPC = curPC; if (curPC < minPC) minPC = curPC;
            // instruction length (from the mirror listing) for return-address computation
            try {
                long la = (curPC >= 0x80000L) ? curPC : curPC + 0x80000L;
                Address lad = toAddr(la);
                ghidra.program.model.listing.Instruction in = getInstructionAt(lad);
                if (in == null) { disassemble(lad); in = getInstructionAt(lad); }
                curLen = (in != null) ? in.getLength() : 2;
            } catch (Throwable t) { curLen = 2; }
            if (lastPC >= 0 && Math.abs(curPC - lastPC) > 6) {  // non-sequential = branch/call/ret
                jmpFrom[ji] = lastPC; jmpTo[ji] = curPC; ji = (ji+1)%40; jmpCount++;
            }
            int c = seen.merge(curPC, 1, Integer::sum);
            if (curPC == lastPC) { if (++stuck > 500) { stop = String.format("stuck @%06X", curPC); break; } }
            else stuck = 0;
            lastPC = curPC;
            if (c > 50000) { stop = String.format("hot loop @%06X (%d)", curPC, c); break; }

            try { if (!emu.step(monitor)) { stop = String.format("step=false @%06X: %s", curPC, emu.getLastError()); break; } }
            catch (Throwable t) { stop = String.format("FAULT @%06X: %s", curPC, t.toString()); break; }

            byte[] cur;
            try { cur = emu.readMemory(sp.getAddress(LO), RN); } catch (Throwable t) { continue; }
            for (int i = 0; i < RN; i++) if (cur[i] != prev[i]) {
                println(String.format("  >>> WRITE pool %04X : %02X -> %02X  @PC %06X",
                        LO+i, prev[i]&0xFF, cur[i]&0xFF, curPC));
                prev[i] = cur[i]; writeHits++;
            }
        }
        println("--- stop: " + stop);
        println(String.format("--- PC range visited: %06X .. %06X", minPC, maxPC));
        println("--- total branches: " + jmpCount + " | last 40 (from -> to):");
        for (int k = 0; k < 40; k++) { int idx = (ji+k)%40;
            if (jmpFrom[idx]!=0 || jmpTo[idx]!=0)
                println(String.format("      %06X -> %06X", jmpFrom[idx], jmpTo[idx])); }
        println("--- instructions: " + seen.values().stream().mapToInt(Integer::intValue).sum()
                + " | distinct PCs: " + seen.size());
        println("--- addrCalc callback fires: " + addrCalcFires
                + " (0 => injector pre-empts, must disable it)");
        println("--- pool address-calcs logged: " + poolAccessLogs + " | pool WRITES: " + writeHits);
        emu.dispose();
    }
}
