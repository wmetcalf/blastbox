// Writes the program's defined data strings to a JSON Lines file for the REA sweep engine.
// Usage (analyzeHeadless): -scriptPath <dir> -postScript ListStrings.java <output.jsonl>
// One {"address":"0x..","value":".."} per line, at most MAX_ENTRIES lines, each value cut to
// MAX_CHARS UTF-16 units (never splitting a surrogate pair). Output is pure ASCII: every
// character outside 0x20..0x7e is written as a JSON backslash-u escape, so the file is valid JSON
// whatever the sample's strings contain.
//@category Loadout
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class ListStrings extends GhidraScript {
    private static final int MAX_ENTRIES = 50000;
    private static final int MAX_CHARS = 4096;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: ListStrings <output.jsonl>");
        }
        int written = 0;
        try (Writer w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.US_ASCII))) {
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
