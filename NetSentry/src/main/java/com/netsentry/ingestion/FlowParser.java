package com.netsentry.ingestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.netsentry.model.FlowRecord;
import com.netsentry.util.IpValidator;
import com.netsentry.util.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class FlowParser {
    public static final long MAX_FILE_BYTES = 10L * 1024 * 1024;
    public static final int MAX_RECORDS = 500_000;
    private static final int MAX_ERRORS = 100;

    public ParseResult parse(Path path) throws IOException {
        if (!Files.isRegularFile(path)) throw new IOException("Input file does not exist or is not a regular file: " + path);
        long size = Files.size(path);
        if (size > MAX_FILE_BYTES) throw new IOException("Input exceeds the 10 MiB upload limit");
        return parse(Files.readAllBytes(path), path.getFileName().toString());
    }

    public ParseResult parse(byte[] bytes, String filename) throws IOException {
        if (bytes == null) throw new IOException("Request body is empty");
        if (bytes.length == 0) throw new IOException("Input file is empty");
        if (bytes.length > MAX_FILE_BYTES) throw new IOException("Input exceeds the 10 MiB upload limit");
        String text = new String(bytes, StandardCharsets.UTF_8);
        String lower = filename == null ? "" : filename.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".json")) return parseJson(text);
        if (lower.endsWith(".csv")) return parseCsv(text);
        throw new IOException("Unsupported file extension. Use .csv or .json");
    }

    private ParseResult parseCsv(String text) throws IOException {
        ParseResult result = new ParseResult();
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        int headerAt = -1;
        List<String> headers = null;
        for (int i = 0; i < lines.length; i++) {
            if (!lines[i].isBlank()) {
                headerAt = i;
                break;
            }
        }
        if (headerAt < 0) throw new IOException("CSV has no header or records");
        try {
            headers = csvLine(lines[headerAt]);
        } catch (IllegalArgumentException ex) {
            throw new IOException("Malformed CSV header: " + ex.getMessage());
        }
        Map<String, Integer> index = new HashMap<>();
        for (int i = 0; i < headers.size(); i++) index.put(headers.get(i).trim().toLowerCase(Locale.ROOT), i);
        for (String required : List.of("timestamp", "srcip", "dstip", "dstport")) {
            if (!index.containsKey(required)) throw new IOException("CSV is missing required column: " + required);
        }
        for (int lineNo = headerAt + 1; lineNo < lines.length; lineNo++) {
            String line = lines[lineNo];
            if (line.isBlank()) continue;
            if (result.totalRows >= MAX_RECORDS) throw new IOException("Input exceeds the 500,000-record limit");
            result.totalRows++;
            try {
                List<String> cells = csvLine(line);
                if (cells.size() != headers.size()) throw new IllegalArgumentException("expected " + headers.size() + " columns but found " + cells.size());
                FlowRecord record = new FlowRecord();
                record.timestamp = cell(cells, index, "timestamp");
                record.srcIp = cell(cells, index, "srcip");
                record.dstIp = cell(cells, index, "dstip");
                record.srcPort = optionalInt(cell(cells, index, "srcport"), "srcPort");
                record.dstPort = optionalInt(cell(cells, index, "dstport"), "dstPort");
                record.protocol = defaultValue(cell(cells, index, "protocol"), "UNKNOWN").toUpperCase(Locale.ROOT);
                record.packets = optionalLong(cell(cells, index, "packets"), "packets");
                record.bytes = optionalLong(cell(cells, index, "bytes"), "bytes");
                record.connectionStatus = defaultValue(cell(cells, index, "connectionstatus"), "UNKNOWN").toUpperCase(Locale.ROOT);
                validate(record);
                result.records.add(record);
            } catch (RuntimeException ex) {
                reject(result, "Line " + (lineNo + 1) + ": " + safeMessage(ex));
            }
        }
        return result;
    }

    private ParseResult parseJson(String text) throws IOException {
        ParseResult result = new ParseResult();
        JsonNode root;
        try {
            root = Json.mapper().readTree(text);
        } catch (Exception ex) {
            throw new IOException("Invalid JSON: " + safeMessage(ex));
        }
        JsonNode rows = root != null && root.isArray() ? root : root == null ? null : root.get("records");
        if (rows == null || !rows.isArray()) throw new IOException("JSON must be an array of flow records or an object with a 'records' array");
        if (rows.size() > MAX_RECORDS) throw new IOException("Input exceeds the 500,000-record limit");
        for (int i = 0; i < rows.size(); i++) {
            result.totalRows++;
            try {
                JsonNode n = rows.get(i);
                if (!n.isObject()) throw new IllegalArgumentException("record must be a JSON object");
                FlowRecord r = new FlowRecord();
                r.timestamp = string(n, "timestamp", true);
                r.srcIp = string(n, "srcIp", true);
                r.dstIp = string(n, "dstIp", true);
                r.srcPort = intNode(n, "srcPort");
                r.dstPort = intNode(n, "dstPort");
                r.protocol = defaultValue(string(n, "protocol", false), "UNKNOWN").toUpperCase(Locale.ROOT);
                r.packets = longNode(n, "packets");
                r.bytes = longNode(n, "bytes");
                r.connectionStatus = defaultValue(string(n, "connectionStatus", false), "UNKNOWN").toUpperCase(Locale.ROOT);
                validate(r);
                result.records.add(r);
            } catch (RuntimeException ex) {
                reject(result, "Record " + (i + 1) + ": " + safeMessage(ex));
            }
        }
        return result;
    }

    private void validate(FlowRecord r) {
        if (r.timestamp == null || r.timestamp.isBlank()) throw new IllegalArgumentException("timestamp is required");
        try {
            r.eventTime = Instant.parse(r.timestamp);
        } catch (Exception first) {
            try {
                r.eventTime = OffsetDateTime.parse(r.timestamp).toInstant();
            } catch (Exception second) {
                throw new IllegalArgumentException("timestamp must be ISO-8601 with a timezone, e.g. 2026-10-27T10:15:30Z");
            }
        }
        r.timestamp = r.eventTime.toString();
        if (!IpValidator.isValid(r.srcIp)) throw new IllegalArgumentException("invalid srcIp: " + r.srcIp);
        if (!IpValidator.isValid(r.dstIp)) throw new IllegalArgumentException("invalid dstIp: " + r.dstIp);
        r.srcIp = r.srcIp.trim();
        r.dstIp = r.dstIp.trim();
        if (r.srcPort != null && (r.srcPort < 0 || r.srcPort > 65535)) throw new IllegalArgumentException("srcPort must be in 0..65535");
        if (r.dstPort == null || r.dstPort < 0 || r.dstPort > 65535) throw new IllegalArgumentException("dstPort is required and must be in 0..65535");
        if (r.packets == null) r.packets = 0L;
        if (r.bytes == null) r.bytes = 0L;
        if (r.packets < 0) throw new IllegalArgumentException("packets cannot be negative");
        if (r.bytes < 0) throw new IllegalArgumentException("bytes cannot be negative");
        if (r.protocol == null || !List.of("TCP", "UDP", "ICMP", "UNKNOWN").contains(r.protocol)) throw new IllegalArgumentException("protocol must be TCP, UDP, ICMP, or UNKNOWN");
        if (r.connectionStatus == null || !List.of("SUCCESS", "FAILED", "UNKNOWN").contains(r.connectionStatus)) throw new IllegalArgumentException("connectionStatus must be SUCCESS, FAILED, or UNKNOWN");
    }

    private static List<String> csvLine(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder value = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    value.append('"');
                    i++;
                } else quoted = !quoted;
            } else if (c == ',' && !quoted) {
                out.add(value.toString());
                value.setLength(0);
            } else value.append(c);
        }
        if (quoted) throw new IllegalArgumentException("unclosed quoted field");
        out.add(value.toString());
        return out;
    }

    private static String cell(List<String> cells, Map<String, Integer> indexes, String name) {
        Integer i = indexes.get(name);
        return i == null ? null : cells.get(i).trim();
    }

    private static String string(JsonNode n, String name, boolean required) {
        JsonNode v = n.get(name);
        if (v == null || v.isNull()) {
            if (required) throw new IllegalArgumentException(name + " is required");
            return null;
        }
        if (!v.isValueNode()) throw new IllegalArgumentException(name + " must be a string");
        return v.asText();
    }

    private static Integer intNode(JsonNode n, String name) {
        JsonNode v = n.get(name);
        if (v == null || v.isNull() || v.asText().isBlank()) return null;
        if (!v.isIntegralNumber() || !v.canConvertToInt()) throw new IllegalArgumentException(name + " must be an integer");
        return v.intValue();
    }

    private static Long longNode(JsonNode n, String name) {
        JsonNode v = n.get(name);
        if (v == null || v.isNull() || v.asText().isBlank()) return null;
        if (!v.isIntegralNumber() || !v.canConvertToLong()) throw new IllegalArgumentException(name + " must be an integer");
        return v.longValue();
    }

    private static Integer optionalInt(String value, String name) {
        if (value == null || value.isBlank()) return null;
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(name + " must be an integer");
        }
    }

    private static Long optionalLong(String value, String name) {
        if (value == null || value.isBlank()) return null;
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(name + " must be an integer");
        }
    }

    private static String defaultValue(String input, String fallback) {
        return input == null || input.isBlank() ? fallback : input.trim();
    }

    private static void reject(ParseResult result, String error) {
        result.rejectedRows++;
        if (result.errors.size() < MAX_ERRORS) result.errors.add(error);
    }

    private static String safeMessage(Throwable ex) {
        return ex.getMessage() == null ? "invalid record" : ex.getMessage();
    }
}
