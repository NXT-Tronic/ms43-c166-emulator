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

// #1 — map EVERY RAM write the MS43 boot performs, to find regions the firmware never
// touches at startup (candidate reset-robust overlay locations). Uses faithful live-DPP
// CALLOTHER callbacks (same as EmuBootF) + the emulator's memory-write tracking.
public class EmuRamMap extends GhidraScript {
    EmulatorHelper emu;
    AddressSpace REG, RAM, CONST;
    long curPC = 0; int curLen = 2;
    static final long IP_REG_OFF = 0x20L;

    long rd(MemoryState ms, Varnode v){ if(v.isConstant()) return v.getOffset();
        return ms.getValue(v.getAddress().getAddressSpace(), v.getOffset(), v.getSize()); }
    void wr(MemoryState ms, Varnode v, long val){ ms.setValue(v.getAddress().getAddressSpace(), v.getOffset(), v.getSize(), val); }
    long dpp(MemoryState ms, int n){ return ms.getValue(REG, 0xFE00L+2L*n, 2) & 0x3FFL; }
    long sp(MemoryState ms){ return ms.getValue(RAM, 0xFE12L, 2) & 0xFFFFL; }
    void setSp(MemoryState ms, long v){ ms.setValue(RAM, 0xFE12L, 2, v & 0xFFFFL); }
    long page(MemoryState ms, long logical){ logical &= 0xFFFF;
        return (dpp(ms,(int)((logical>>14)&3))<<14) | (logical & 0x3FFF); }

    abstract class Op extends BreakCallBack {
        public boolean pcodeCallback(PcodeOpRaw op){ handle(emulate.getMemoryState(), op); return true; }
        abstract void handle(MemoryState ms, PcodeOpRaw op);
    }

    @Override public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        emu = new EmulatorHelper(currentProgram);
        REG = emu.getLanguage().getAddressFactory().getRegisterSpace();
        RAM = emu.getLanguage().getAddressFactory().getDefaultAddressSpace();
        CONST = emu.getLanguage().getAddressFactory().getConstantSpace();
        emu.setMemoryFaultHandler(new MemoryFaultHandler(){
            public boolean uninitializedRead(Address a,int s,byte[] b,int o){return true;}
            public boolean unknownAddress(Address a,boolean w){return true;} });

        emu.registerCallOtherCallback("GetPagedOffset", new Op(){ void handle(MemoryState ms,PcodeOpRaw op){
            wr(ms, op.getOutput(), page(ms, rd(ms,op.getInput(1))&0xFFFF)); }});
        emu.registerCallOtherCallback("c166_reg_offset_addr", new Op(){ void handle(MemoryState ms,PcodeOpRaw op){
            long reg=rd(ms,op.getInput(1))&0xFFFF, imm=rd(ms,op.getInput(2))&0xFFFF;
            wr(ms, op.getOutput(), page(ms,(reg+imm)&0xFFFF)); }});
        emu.registerCallOtherCallback("segment", new Op(){ void handle(MemoryState ms,PcodeOpRaw op){
            long seg=rd(ms,op.getInput(1))&0xFF, off=rd(ms,op.getInput(2))&0xFFFF;
            wr(ms, op.getOutput(), (seg<<16)|off); }});
        emu.registerCallOtherCallback("push", new Op(){ void handle(MemoryState ms,PcodeOpRaw op){
            Varnode in=op.getInput(1); long val;
            if(in.getAddress().getAddressSpace().equals(REG)&&in.getOffset()==IP_REG_OFF&&in.getSize()==2) val=(curPC+curLen)&0xFFFF;
            else val=rd(ms,in);
            long s=(sp(ms)-2)&0xFFFF; setSp(ms,s); ms.setValue(RAM,s,2,val&0xFFFF); }});
        emu.registerCallOtherCallback("pop", new Op(){ void handle(MemoryState ms,PcodeOpRaw op){
            long s=sp(ms); long val=ms.getValue(RAM,s,2)&0xFFFF; wr(ms,op.getInput(1),val); setSp(ms,(s+2)&0xFFFF); }});
        emu.registerDefaultCallOtherCallback(new Op(){ void handle(MemoryState ms,PcodeOpRaw op){} });

        byte[] low = new byte[0xE000];
        currentProgram.getMemory().getBytes(sp.getAddress(0x80000L), low);
        emu.writeMemory(sp.getAddress(0L), low);
        emu.writeRegister("DPP0",0); emu.writeRegister("DPP1",1); emu.writeRegister("DPP2",2); emu.writeRegister("DPP3",3);
        emu.writeMemory(sp.getAddress(0xFE12L), new byte[]{(byte)0x9C,(byte)0xF8});
        try{ emu.writeRegister("CSP",0);}catch(Throwable t){}
        emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(0x2D06L));

        emu.enableMemoryWriteTracking(true);

        int MAX = 4_000_000;
        long lastPC=-1; int stuck=0; String stop="step cap"; long mark=0;
        for(int s=0; s<MAX; s++){
            try{ curPC=emu.getExecutionAddress().getOffset(); }catch(Throwable t){ stop="no PC: "+t; break; }
            try{ long la=(curPC>=0x80000L)?curPC:curPC+0x80000L; Address lad=toAddr(la);
                ghidra.program.model.listing.Instruction in=getInstructionAt(lad);
                if(in==null){ disassemble(lad); in=getInstructionAt(lad); }
                curLen=(in!=null)?in.getLength():2; }catch(Throwable t){ curLen=2; }
            if(curPC==lastPC){ if(++stuck>2000){ stop=String.format("stuck @%06X",curPC); break; } } else stuck=0;
            lastPC=curPC;
            try{ if(!emu.step(monitor)){ stop=String.format("step=false @%06X: %s",curPC,emu.getLastError()); break; } }
            catch(Throwable t){ stop=String.format("FAULT @%06X: %s",curPC,t.toString()); break; }
            if((s & 0x7FFFF)==0){ println("  ... "+s+" instrs, PC "+String.format("%06X",curPC)); }
        }
        println("--- stop: "+stop);

        // report tracked writes in the data/default space (RAM + any flash-mirror writes)
        AddressSetView w = emu.getTrackedMemoryWriteSet();
        println("=== MEMORY WRITES during boot (default space, offset < 0x80000 = RAM-ish) ===");
        long ramWritten=0;
        for(AddressRange r : w){
            Address st=r.getMinAddress();
            if(!st.getAddressSpace().equals(RAM)) continue;
            long a=st.getOffset(), b=r.getMaxAddress().getOffset();
            if(a>=0x80000L) continue;                 // skip flash region
            ramWritten += (b-a+1);
            println(String.format("   WROTE %05X - %05X  (%d B)", a, b, b-a+1));
        }
        println("   total RAM bytes written: "+ramWritten);

        // gaps (never written) within the known small RAMs
        reportGaps(w, "XRAM", 0xE000L, 0xE7FFL);
        reportGaps(w, "IRAM/DPRAM", 0xF600L, 0xFDFFL);
        emu.dispose();
    }

    void reportGaps(AddressSetView w, String name, long lo, long hi){
        println(String.format("=== UNWRITTEN gaps in %s 0x%04X-0x%04X (free candidates) ===", name, lo, hi));
        long runStart=-1; int gaps=0;
        for(long a=lo; a<=hi+1; a++){
            boolean written = (a<=hi) && w.contains(RAM.getAddress(a));
            if(!written && a<=hi){ if(runStart<0) runStart=a; }
            else { if(runStart>=0){ long len=a-runStart;
                if(len>=8){ println(String.format("   FREE %04X-%04X  (%d B)", runStart, a-1, len)); gaps++; }
                runStart=-1; } }
        }
        if(gaps==0) println("   (none >=8 B)");
    }
}
