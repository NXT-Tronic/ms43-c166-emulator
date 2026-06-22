# ms43-emulator

A **faithful C166/C167 PCode emulation harness for Ghidra**, specialised for the BMW
**MS43** (Siemens) engine ECU. It runs the firmware's real boot/runtime code inside Ghidra's
emulator and resolves **DPP-paged data addresses from the *live* registers** — something neither
plain static cross-referencing nor the stock C166 processor module can do, because on the C166
a 16-bit operand maps to a physical page chosen at runtime by the `DPP` registers.

> **No firmware is included.** The MS43 firmware image is proprietary (BMW/Siemens). You supply
> your own dump. These scripts only read bytes from an image you load yourself into a Ghidra
> project. Nothing here embeds or redistributes calibration data or firmware.

## Why this exists

On the MS43 (C167 core, Tasking toolchain) you cannot answer questions like *"does the boot
sector write to XRAM region X?"* by static analysis:

- **DPP indirection** — operand `0xE694` ≠ physical XRAM `0xE694`; the page comes from a runtime
  `DPP` register.
- The stock C166 module's pcode **injector** resolves paged addresses from the *static* analysis
  context (it bakes a constant), so even emulating through it reproduces the static assumption.

This harness sidesteps both by **re-implementing the C166 `CALLOTHER` pcodeops** (`GetPagedOffset`,
`c166_reg_offset_addr`, `segment`, `push`, `pop`) as Ghidra `BreakCallBack`s that compute addresses
from the **live** `DPP`/registers in the emulator — so every load/store resolves to its true
runtime physical address.

## What it produced

Driving `EmuBootF` from the reset vector, the emulator executes real boot flow (loops,
calls/returns) and traces every write into a target window. It revealed that **MS43 boot runs a
destructive power-on RAM test** (walking-bit + `0x5555`/`0xAAAA` patterns) over **`0xE000–0xE7D6`**
and **`0xF620–0xFDFE`** — i.e. it writes those regions at every startup, *before* the application
connects. (Useful to know when picking "free" RAM for a live-tuning overlay: such a region is safe
for a *post-boot-armed* table, but a watchdog/soft reset re-runs the test.)

## Requirements

- **Ghidra 12.1.x** (developed on 12.1.2)
- **JDK 21** (Ghidra 12 needs 21)
- **C166 processor module**: [c166-ghidra-module](https://github.com/) (language id `C166:LE:16:default`,
  compiler `tasking`). One known fix on some builds: remove `<register name="CP"/>` from
  `c166.cspec` if 12.1.2 rejects it.
- Your own MS43 firmware dump (512 KB).

## Setup

1. Create a Ghidra project and import your firmware **raw**, base **`0x80000`**, processor
   `C166:LE:16:default`. Define the C166 data blocks (XRAM `0xE000–0xE7FF`, IRAM `0xF600–0xFDFF`,
   SFR `0xFE00–0xFFFF`, etc.) and the flash block `0x80000–0xFFFFF`. (The scripts also mirror the
   low flash window `0x0–0xDFFF` into the emulator so segment-0 reset code resolves.)
2. Put the `scripts/` folder on your Ghidra `-scriptPath`.

## Usage (headless)

```sh
GH=/path/to/ghidra_12.1.2_PUBLIC
"$GH/support/analyzeHeadless.bat" /path/to/projectDir ProjectName \
   -process -noanalysis -scriptPath ./scripts -postScript EmuBootF.java
```

`EmuBootF.java` (edit the `LO`/`HI` constants for your target window) prints every write into the
window with its **live-resolved physical address** and the PC that wrote it, plus a branch trace
and a summary. Compile-check a script standalone (OSGi hides headless compile errors):

```sh
javac -proc:none -cp "$(find $GH/Ghidra -name '*.jar' | tr '\n' ';')" -d /tmp EmuBootF.java
```

## Scripts

| script | purpose |
|---|---|
| `EmuBootF.java` | **the emulator** — live-DPP CALLOTHER callbacks, boot trace, write logging into a target window |
| `RamMap.java`   | static reference map of RAM ranges (fast first pass; DPP-limited) |
| `XrefProbe.java` / `XrefDeep.java` | list references into an address range (with seeding/flow) |
| `DumpAt.java`   | targeted disassembly dump at an address |

## Key C166 emulation notes (for hackers extending this)

- **System stack** uses the **SP SFR at `0xFE12`** (init `0xF89C` on MS43), *not* `r0`. The Tasking
  compiler uses `r0` as a separate *user* stack (`mov [-r0],reg`); the module's `stackpointer=r0`
  cspec is a decompiler convention, so hardware `push`/`pop`/`call`/`ret` must target the SP SFR.
- `IP` is the 17th word register (block `[r0..r15 IP]`, reg-offset `0x20`) and is a scratch target
  for jumps; it is **not** `inst_next`, so `push(IP)` (the call return-save) must push
  `currentPC + instruction_length`.
- The emulator does **not** pre-empt CALLOTHER with the module's injector — your
  `registerCallOtherCallback` handlers are authoritative.
- System ops (`__nop`, `__disable_watchdog`, `__end_of_init`, `__idle`, …) are no-oped via
  `registerDefaultCallOtherCallback`.

## License

MIT — see [LICENSE](LICENSE). This is interoperability/research tooling; it contains no
manufacturer firmware or calibration data.
