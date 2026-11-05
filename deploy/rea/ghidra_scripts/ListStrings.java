// Writes the program's defined data strings to a JSON Lines file for the REA sweep engine.
// Usage (analyzeHeadless): -scriptPath <dir> -postScript ListStrings.java <output.jsonl>
// The first line is {"function_count":N,"image_base":"0x.."} (non-external functions, counted up
// to MAX_FUNCTIONS, for the sweep's packed-sample check; the image base, to move capa's
// addresses into Ghidra's image). Then one {"address":"0x..","value":".."} per line, at most MAX_ENTRIES lines, each value cut to
// MAX_CHARS UTF-16 units (never splitting a surrogate pair). Output is pure ASCII: every
// character outside 0x20..0x7e is written as a JSON backslash-u escape, so the file is valid JSON
// whatever the sample's strings contain.
//@category Loadout
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class ListStrings extends GhidraScript {
    private static final int MAX_ENTRIES = 50000;
    private static final int MAX_CHARS = 4096;
    private static final int MAX_FUNCTIONS = 1000000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: ListStrings <output.jsonl>");
        }
        int written = 0;
        try (Writer w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.US_ASCII))) {
            w.write("{\"function_count\":");
            w.write(Integer.toString(countFunctions()));
            w.write(",\"image_base\":\"0x");
            w.write(currentProgram.getImageBase().toString(false));
            w.write("\"}\n");
            DataIterator it = currentProgram.getListing().getDefinedData(true);
            while (it.hasNext() && written < MAX_ENTRIES && !monitor.isCancelled()) {
                Data d = it.next();
                if (!StringDataInstance.isString(d)) {
                    continue;
                }
                String v = StringDataInstance.getStringDataInstance(d).getStringValue();
                if (v == null || v.isEmpty()) {
                    continue;
                }
                if (v.length() > MAX_CHARS) {
                    int cut = MAX_CHARS;
                    if (Character.isHighSurrogate(v.charAt(cut - 1))) {
                        cut--;
                    }
                    v = v.substring(0, cut);
                }
                w.write("{\"address\":\"0x");
                w.write(d.getAddress().toString(false));
                w.write("\",\"value\":\"");
                escape(w, v);
                w.write("\"}\n");
                written++;
            }
        }
        println("ListStrings: wrote " + written + " strings");
    }

    private int countFunctions() {
        // getFunctions(true) iterates non-external functions only; getFunctionCount() includes
        // externals, which would hide a packer stub's handful of real procedures.
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        int n = 0;
        while (fi.hasNext() && n < MAX_FUNCTIONS && !monitor.isCancelled()) {
            fi.next();
            n++;
        }
        return n;
    }

    private static void escape(Writer w, String s) throws java.io.IOException {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') {
                w.write("\\\"");
            } else if (c == '\\') {
                w.write("\\\\");
            } else if (c < 0x20 || c > 0x7e) {
                w.write(String.format("\\u%04x", (int) c));
            } else {
                w.write(c);
            }
        }
    }
}
