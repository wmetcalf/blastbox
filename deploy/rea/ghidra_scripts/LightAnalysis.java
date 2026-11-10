// Trimmed auto-analysis profile for the REA sweep's "light" Ghidra import.
// Usage (analyzeHeadless): -scriptPath <dir> -preScript LightAnalysis.java
// Runs before auto-analysis and switches off the analyzers that dominated the measured time on
// the samples that blew the sweep's 420 s budget (Ghidra 12.1.4, -max-cpu 2, 6 GB slot):
//   Decompiler Parameter ID      decompiles every function; on by default for any PE under 2 MiB of
//                                address space. 435 s of 629 s on an 800 KB .NET assembly, 155 s
//                                of 474 s on a 655 KB PE32+ DLL
//   Call Convention ID           decompiler-driven too; 179 s on the same .NET assembly
//   Decompiler Switch Analysis   decompiles every function holding an indirect jump; 1744 s of
//                                2340 s on a 6.5 MB Rust PE, 260 s on the DLL
//   Stack                        156 s on a 12.5 MB Go PE, 238 s on a 7.6 MB PE32+ DLL
//   x86 Constant Reference Analyzer   121 s on the Go PE, 228 s on the 7.6 MB DLL
// The agent decompiles on demand through REA's MCP server, and the decompiler recovers
// parameters, switches and stack frames itself at that point; what the light project loses is the
// committed signatures/stack variables at callers and some constant-derived references (fewer
// xrefs; 8% fewer functions on a Go PE, within 0.5% elsewhere). Function discovery, strings, imports,
// Function ID, demanglers and the Go/Rust analyzers stay on.
// An option the program does not have (an analyzer that does not apply to its format or processor)
// is skipped. The output names each analyzer it disabled.
//@category Loadout
import ghidra.app.script.GhidraScript;

import java.util.Map;

public class LightAnalysis extends GhidraScript {
    static final String[] DISABLED = {
        "Decompiler Parameter ID",
        "Call Convention ID",
        "Decompiler Switch Analysis",
        "Stack",
        "x86 Constant Reference Analyzer",
    };

    @Override
    public void run() throws Exception {
        Map<String, String> current = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String name : DISABLED) {
            if (!current.containsKey(name)) {
                continue;
            }
            setAnalysisOption(currentProgram, name, "false");
            println("LightAnalysis: disabled " + name);
        }
    }
}
