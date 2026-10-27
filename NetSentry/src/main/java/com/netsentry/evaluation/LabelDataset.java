package com.netsentry.evaluation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Loads source-host labels from a CSV with srcIp,label columns. */
public final class LabelDataset {

    private LabelDataset() {
    }

    public static Map<String, Boolean> read(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        if (lines.isEmpty()) throw new IOException("Label file is empty");
        String[] header = lines.get(0).split(",", -1);
        int ipColumn = -1, labelColumn = -1;
        for (int i = 0; i < header.length; i++) {
            String h = header[i].trim().toLowerCase(Locale.ROOT);
            if (h.equals("srcip")) ipColumn = i;
            if (h.equals("label")) labelColumn = i;
        }
        if (ipColumn < 0 || labelColumn < 0) throw new IOException("Label CSV must have srcIp,label columns");
        Map<String, Boolean> labels = new LinkedHashMap<>();
        for (int lineNo = 1; lineNo < lines.size(); lineNo++) {
            String line = lines.get(lineNo).trim();
            if (line.isEmpty()) continue;
            String[] cells = line.split(",", -1);
            if (cells.length != header.length) throw new IOException("Invalid label row at line " + (lineNo + 1));
            String ip = cells[ipColumn].trim();
            String label = cells[labelColumn].trim().toUpperCase(Locale.ROOT);
            if (ip.isEmpty()) throw new IOException("Missing srcIp at line " + (lineNo + 1));
            boolean suspicious;
            if (label.equals("SUSPICIOUS")) suspicious = true;
            else if (label.equals("NORMAL")) suspicious = false;
            else throw new IOException("Label at line " + (lineNo + 1) + " must be SUSPICIOUS or NORMAL");
            if (labels.putIfAbsent(ip, suspicious) != null) throw new IOException("Duplicate srcIp in labels: " + ip);
        }
        if (labels.isEmpty()) throw new IOException("Label file contains no labelled hosts");
        return labels;
    }
}
