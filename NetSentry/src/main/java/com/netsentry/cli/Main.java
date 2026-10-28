package com.netsentry.cli;

import com.netsentry.api.ApiServer;
import com.netsentry.evaluation.EvaluationMetrics;
import com.netsentry.evaluation.LabelDataset;
import com.netsentry.config.ConfigLoader;
import com.netsentry.config.RulesConfig;
import com.netsentry.detection.DetectionEngine;
import com.netsentry.ingestion.FlowParser;
import com.netsentry.history.AnalysisHistoryEntry;
import com.netsentry.history.AnalysisHistoryService;
import com.netsentry.ingestion.ParseResult;
import com.netsentry.model.AnalysisResult;
import com.netsentry.model.FlowRecord;
import com.netsentry.reporting.ReportService;
import com.netsentry.util.Json;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Exception ex) {
            System.err.println(
                    "NetSentry: " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage()));
            System.exit(1);
        }
    }

    private static void run(String[] args) throws Exception {
        if (args.length == 0) {
            web(envPort());
            return;
        }
        String command = args[0].toLowerCase(Locale.ROOT);
        switch (command) {
            case "web" -> web(parsePort(args));
            case "analyze" -> analyze(args);
            case "validate" -> validate(args);
            case "rules" -> System.out.println(Json.mapper().writeValueAsString(ConfigLoader.loadDefault()));
            case "benchmark" -> benchmark(args);
            case "evaluate" -> evaluate(args);
            case "history" -> history(args);
            case "version" ->
                System.out.println("NetSentry " + ApiServer.VERSION + " | Java " + Runtime.version().feature());
            case "help", "--help", "-h" -> help();
            default -> {
                System.err.println("Unknown command: " + args[0]);
                help();
                System.exit(2);
            }
        }
    }

    private static int parsePort(String[] args) {
        for (int i = 1; i < args.length; i++)
            if (args[i].equals("--port") && i + 1 < args.length) {
                try {
                    int p = Integer.parseInt(args[i + 1]);
                    if (p < 1024 || p > 65535)
                        throw new IllegalArgumentException("Port must be in 1024..65535");
                    return p;
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("Port must be a number");
                }
            }
        return envPort();
    }

    private static int envPort() {
        String env = System.getenv("PORT");
        if (env != null && !env.isBlank()) {
            try {
                int p = Integer.parseInt(env.trim());
                if (p >= 1024 && p <= 65535)
                    return p;
            } catch (NumberFormatException ignored) {
            }
        }
        return 8080;
    }

    private static void web(int port) throws Exception {
        RulesConfig config = ConfigLoader.loadDefault();
        config.validate();
        new ApiServer(port, config).start();
    }

    private static void analyze(String[] args) throws Exception {
        String input = option(args, "--input", null);
        if (input == null)
            throw new IllegalArgumentException("analyze requires --input <file>");
        String format = option(args, "--format", "json").toLowerCase(Locale.ROOT);
        String output = option(args, "--output", null);
        if (!format.equals("json") && !format.equals("csv"))
            throw new IllegalArgumentException("--format must be json or csv");
        FlowParser parser = new FlowParser();
        ParseResult parsed = parser.parse(Path.of(input));
        AnalysisResult result = new DetectionEngine().analyze(parsed, Path.of(input).getFileName().toString(),
                ConfigLoader.loadDefault());
        AnalysisHistoryEntry historyEntry = new AnalysisHistoryService().save(result);
        ReportService reports = new ReportService();
        String payload = format.equals("csv") ? reports.alertsAsCsv(result.alerts) : reports.asJson(result);
        if (output != null) {
            Path out = Path.of(output);
            if (out.toAbsolutePath().getParent() != null)
                Files.createDirectories(out.toAbsolutePath().getParent());
            Files.writeString(out, payload);
            System.out.println("Report written: " + out.toAbsolutePath());
        } else
            System.out.println(payload);
        System.out.printf(Locale.ROOT, "\nAccepted %d/%d records; rejected %d; alerts %d; processing %d ms%n",
                result.acceptedRecords, result.totalRecords, result.rejectedRecords, result.alertCount,
                result.durationMs);
        System.out.println("History ID: " + historyEntry.id);
    }

    private static void validate(String[] args) throws Exception {
        String input = option(args, "--input", null);
        if (input == null)
            throw new IllegalArgumentException("validate requires --input <file>");
        ParseResult parsed = new FlowParser().parse(Path.of(input));
        System.out.printf(Locale.ROOT, "Input: %s%nTotal records: %d%nAccepted: %d%nRejected: %d%n", input,
                parsed.totalRows, parsed.records.size(), parsed.rejectedRows);
        for (String e : parsed.errors)
            System.out.println(" - " + e);
        if (parsed.rejectedRows > 0)
            System.exit(2);
    }

    private static void evaluate(String[] args) throws Exception {
        String input = option(args, "--input", null);
        String labelsPath = option(args, "--labels", null);
        if (input == null || labelsPath == null)
            throw new IllegalArgumentException(
                    "evaluate requires --input <flows.csv|flows.json> --labels <ground-truth.csv>");
        ParseResult parsed = new FlowParser().parse(Path.of(input));
        AnalysisResult result = new DetectionEngine().analyze(parsed, Path.of(input).getFileName().toString(),
                ConfigLoader.loadDefault());
        var labels = LabelDataset.read(Path.of(labelsPath));
        java.util.Set<String> predicted = new java.util.HashSet<>();
        result.alerts.stream().map(a -> a.srcIp).filter(java.util.Objects::nonNull).forEach(predicted::add);
        long tp = 0, fp = 0, fn = 0, tn = 0;
        for (var entry : labels.entrySet()) {
            boolean expected = entry.getValue();
            boolean actual = predicted.contains(entry.getKey());
            if (expected && actual)
                tp++;
            else if (!expected && actual)
                fp++;
            else if (expected)
                fn++;
            else
                tn++;
        }
        EvaluationMetrics metrics = new EvaluationMetrics(tp, fp, fn, tn);
        System.out.println("Source-host detection evaluation (labels are the ground truth; alerts are predictions)");
        System.out.printf(Locale.ROOT, "labelledHosts=%d alerts=%d%nTP=%d FP=%d FN=%d TN=%d%n", labels.size(),
                result.alertCount, tp, fp, fn, tn);
        System.out.printf(Locale.ROOT, "precision=%.4f recall=%.4f F1=%.4f accuracy=%.4f%n", metrics.precision(),
                metrics.recall(), metrics.f1(), metrics.accuracy());
        System.out.println(
                "Note: metrics apply only to the labelled source hosts and this dataset/configuration; they are not a universal accuracy claim.");
    }

    private static void benchmark(String[] args) throws Exception {
        String sizesText = option(args, "--sizes", "10000,100000");
        List<Integer> sizes = new ArrayList<>();
        for (String v : sizesText.split(",")) {
            int n = Integer.parseInt(v.trim());
            if (n < 1 || n > FlowParser.MAX_RECORDS)
                throw new IllegalArgumentException("benchmark sizes must be 1..500000");
            sizes.add(n);
        }
        RulesConfig config = ConfigLoader.loadDefault();
        config.portScan.enabled = false;
        config.connectionBurst.enabled = false;
        config.failedConnections.enabled = false;
        config.hostSweep.enabled = false;
        System.out.println("Synthetic benchmark; measured locally on this JVM (not a universal performance claim).");
        System.out.printf(Locale.ROOT, "java=%s vm=%s os=%s/%s processors=%d maxHeapMiB=%.1f%n",
                System.getProperty("java.version"), System.getProperty("java.vm.name"), System.getProperty("os.name"),
                System.getProperty("os.arch"), Runtime.getRuntime().availableProcessors(),
                Runtime.getRuntime().maxMemory() / (1024.0 * 1024.0));
        for (int n : sizes) {
            ParseResult parsed = new ParseResult();
            parsed.totalRows = n;
            Random random = new Random(42);
            Instant base = Instant.parse("2026-10-27T00:00:00Z");
            for (int i = 0; i < n; i++) {
                FlowRecord r = new FlowRecord();
                r.eventTime = base.plusSeconds(i % 600);
                r.timestamp = r.eventTime.toString();
                r.srcIp = "10.0." + ((i / 250) % 250) + "." + (1 + i % 250);
                r.dstIp = "192.0.2." + (1 + random.nextInt(250));
                r.dstPort = 443;
                r.srcPort = 30000 + i % 30000;
                r.protocol = "TCP";
                r.packets = 1L;
                r.bytes = 512L;
                r.connectionStatus = "SUCCESS";
                parsed.records.add(r);
            }
            long beforeMemory = usedMemory();
            long started = System.nanoTime();
            AnalysisResult r = new DetectionEngine().analyze(parsed, "synthetic-benchmark-" + n, config);
            long elapsedNanos = System.nanoTime() - started;
            long delta = usedMemory() - beforeMemory;
            System.out.printf(Locale.ROOT,
                    "records=%d elapsedMs=%.3f recordsPerSecond=%.0f alerts=%d approxHeapDeltaMiB=%.2f (no GC normalization)%n",
                    n, elapsedNanos / 1_000_000.0, elapsedNanos == 0 ? 0 : n * 1_000_000_000.0 / elapsedNanos,
                    r.alertCount, delta / (1024.0 * 1024.0));
        }
    }

    private static void history(String[] args) throws Exception {
        if (args.length < 2)
            throw new IllegalArgumentException(
                    "history requires list, show <id>, delete <id>, or export <id> --output <file>");
        AnalysisHistoryService service = new AnalysisHistoryService();
        switch (args[1].toLowerCase(Locale.ROOT)) {
            case "list" -> {
                List<AnalysisHistoryEntry> entries = service.list();
                if (entries.isEmpty()) {
                    System.out.println("No analysis history yet.");
                    return;
                }
                for (AnalysisHistoryEntry e : entries)
                    System.out.printf(Locale.ROOT, "%s | %s | %s | records=%d | alerts=%d | duration=%dms%n", e.id,
                            e.timestamp, e.datasetName, e.acceptedRecords, e.alertCount, e.durationMs);
            }
            case "show" -> {
                requireHistoryId(args);
                AnalysisHistoryEntry e = service.get(args[2]);
                if (e == null)
                    throw new IllegalArgumentException("History record not found");
                System.out.println(Json.mapper().writeValueAsString(e));
            }
            case "delete" -> {
                requireHistoryId(args);
                if (service.delete(args[2]))
                    System.out.println("Deleted history record " + args[2]);
                else
                    System.out.println("History record not found.");
            }
            case "export" -> {
                requireHistoryId(args);
                String output = option(args, "--output", null);
                if (output == null)
                    throw new IllegalArgumentException("history export requires --output <file>");
                System.out.println("Exported: " + service.export(args[2], Path.of(output)));
            }
            default -> throw new IllegalArgumentException("Unknown history action: " + args[1]);
        }
    }

    private static void requireHistoryId(String[] args) {
        if (args.length < 3)
            throw new IllegalArgumentException("This history action requires an analysis ID");
    }

    private static long usedMemory() {
        Runtime r = Runtime.getRuntime();
        return r.totalMemory() - r.freeMemory();
    }

    private static String option(String[] args, String key, String fallback) {
        for (int i = 1; i < args.length; i++)
            if (args[i].equals(key)) {
                if (i + 1 >= args.length)
                    throw new IllegalArgumentException("Missing value for " + key);
                return args[i + 1];
            }
        return fallback;
    }

    private static void help() {
        System.out.println(
                """
                        NetSentry - local network-flow analysis and heuristic alerting
                        Usage:
                          java -jar target/netsentry.jar [web [--port 8080]]
                          java -jar target/netsentry.jar analyze --input samples/normal.csv [--format json|csv] [--output reports/alerts.json]
                          java -jar target/netsentry.jar validate --input samples/mixed.csv
                          java -jar target/netsentry.jar rules
                          java -jar target/netsentry.jar benchmark [--sizes 1000,10000,100000]
                          java -jar target/netsentry.jar evaluate --input samples/mixed.csv --labels samples/mixed-ground-truth.csv
                          java -jar target/netsentry.jar history list|show <id>|delete <id>|export <id> --output <file>
                          java -jar target/netsentry.jar version
                          java -jar target/netsentry.jar help
                        Alerts are heuristic indicators and do not prove that an attack occurred.
                        """);
    }
}