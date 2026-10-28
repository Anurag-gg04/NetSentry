package com.netsentry.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.netsentry.config.RulesConfig;
import com.netsentry.detection.DetectionEngine;
import com.netsentry.detection.AlertCorrelationService;
import com.netsentry.ingestion.FlowParser;
import com.netsentry.history.AnalysisHistoryService;
import com.netsentry.incidents.Incident;
import com.netsentry.incidents.IncidentService;
import com.netsentry.ingestion.ParseResult;
import com.netsentry.model.Alert;
import com.netsentry.model.AnalysisResult;
import com.netsentry.reporting.ReportService;
import com.netsentry.util.Json;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;

public class ApiServer {
    public static final String VERSION = "1.0.0";
    private final int port;
    private final RulesConfig config;
    private final FlowParser parser = new FlowParser();
    private final DetectionEngine engine = new DetectionEngine();
    private final AlertCorrelationService correlations = new AlertCorrelationService();
    private final ReportService reports = new ReportService();
    private final AnalysisHistoryService history = new AnalysisHistoryService();
    private final IncidentService incidents = new IncidentService();
    private final AtomicReference<AnalysisResult> latest = new AtomicReference<>();
    private HttpServer server;
    private ExecutorService executor;
    private static final long MAX_BODY = FlowParser.MAX_FILE_BYTES;
    private static final List<Map<String, String>> SAMPLE_LIST = List.of(
            sample("normal.csv", "Normal mixed application traffic"),
            sample("port-scan.csv", "Synthetic scan across many destination ports"),
            sample("connection-burst.csv", "Synthetic high connection volume"),
            sample("failed-connections.csv", "Synthetic repeated failed connections"),
            sample("traffic-spike.csv", "Synthetic traffic spike against quiet baseline buckets"),
            sample("host-sweep.csv", "Synthetic source contacting many distinct destination hosts"),
            sample("mixed.csv", "Normal and suspicious records together"),
            sample("malformed.csv", "Intentionally malformed records for validation testing"));

    public ApiServer(int port, RulesConfig config) {
        this.port = port;
        this.config = config;
    }

    public void start() throws IOException {
        String host = System.getenv().getOrDefault("HOST", "127.0.0.1");
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.createContext("/api/", this::handleApi);
        server.createContext("/", this::handleStatic);
        executor = Executors.newFixedThreadPool(Math.min(16, Math.max(4, Runtime.getRuntime().availableProcessors())));
        server.setExecutor(executor);
        server.start();
        System.out.println("NetSentry " + VERSION + " dashboard on " + host + ":" + port);
        System.out.println("Press Ctrl+C to stop.");
    }

    public int actualPort() {
        return server == null ? port : server.getAddress().getPort();
    }

    public void stop() {
        if (server != null)
            server.stop(0);
        if (executor != null)
            executor.shutdownNow();
    }

    private void handleApi(HttpExchange x) throws IOException {
        addCors(x);
        String path = x.getRequestURI().getPath();
        String method = x.getRequestMethod().toUpperCase(Locale.ROOT);
        try {
            if (method.equals("OPTIONS")) {
                x.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                x.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
                send(x, 204, "", "text/plain; charset=utf-8");
                return;
            }
            if (path.equals("/api/history") && method.equals("GET")) {
                json(x, 200, history.list());
                return;
            }
            if (path.startsWith("/api/history/") && (method.equals("GET") || method.equals("DELETE"))) {
                String id = path.substring("/api/history/".length());
                if (id.contains("/") || id.isBlank()) {
                    json(x, 400, error("INVALID_ID", "Provide one analysis ID."));
                    return;
                }
                if (method.equals("DELETE")) {
                    if (history.delete(id))
                        json(x, 200, Map.of("status", "deleted", "id", id));
                    else
                        json(x, 404, error("NOT_FOUND", "History record not found."));
                    return;
                }
                var entry = history.get(id);
                if (entry == null)
                    json(x, 404, error("NOT_FOUND", "History record not found."));
                else
                    json(x, 200, entry);
                return;
            }
            if (path.equals("/api/incidents") && method.equals("GET")) {
                json(x, 200, incidents.list());
                return;
            }
            if (path.equals("/api/incidents") && method.equals("POST")) {
                createIncident(x);
                return;
            }
            if (path.startsWith("/api/incidents/") && (method.equals("PUT") || method.equals("DELETE"))) {
                String id = path.substring("/api/incidents/".length());
                if (id.contains("/") || id.isBlank()) {
                    json(x, 400, error("INVALID_ID", "Provide one incident ID."));
                    return;
                }
                if (method.equals("DELETE")) {
                    if (incidents.delete(id))
                        json(x, 200, Map.of("status", "deleted", "id", id));
                    else
                        json(x, 404, error("NOT_FOUND", "Incident not found."));
                    return;
                }
                JsonNode node = Json.mapper().readTree(readLimited(x.getRequestBody()));
                Incident updated = incidents.update(id, textField(node, "status"), textField(node, "assignedTo"),
                        textField(node, "notes"));
                if (updated == null)
                    json(x, 404, error("NOT_FOUND", "Incident not found."));
                else
                    json(x, 200, updated);
                return;
            }
            if (path.equals("/api/health") && method.equals("GET")) {
                json(x, 200, Map.of("status", "UP", "version", VERSION, "timestamp", Instant.now().toString()));
                return;
            }
            if (path.equals("/api/stats") && method.equals("GET")) {
                AnalysisResult a = latest.get();
                if (a == null) {
                    json(x, 200, Map.of("status", "empty", "message", "Analyse a dataset to see statistics."));
                    return;
                }
                Map<String, Object> stats = new LinkedHashMap<>();
                stats.put("status", a.status);
                stats.put("datasetName", a.datasetName);
                stats.put("analysisTimestamp", a.analysisTimestamp);
                stats.put("durationMs", a.durationMs);
                stats.put("totalRecords", a.totalRecords);
                stats.put("acceptedRecords", a.acceptedRecords);
                stats.put("rejectedRecords", a.rejectedRecords);
                stats.put("recordsPerSecond", Math.round(a.recordsPerSecond * 100.0) / 100.0);
                stats.put("alertCount", a.alertCount);
                stats.put("severityCounts", a.severityCounts);
                stats.put("trafficTrend", a.trafficTrend);
                json(x, 200, stats);
                return;
            }
            if (path.equals("/api/alerts") && method.equals("GET")) {
                sendAlerts(x);
                return;
            }
            if (path.equals("/api/correlations") && method.equals("GET")) {
                AnalysisResult a = latest.get();
                json(x, 200, correlations.correlate(a == null ? List.of() : a.alerts));
                return;
            }
            if (path.equals("/api/rules") && method.equals("GET")) {
                json(x, 200, config);
                return;
            }
            if (path.equals("/api/samples") && method.equals("GET")) {
                json(x, 200, SAMPLE_LIST);
                return;
            }
            if (path.equals("/api/analyze") && method.equals("POST")) {
                analyzeUpload(x);
                return;
            }
            if (path.equals("/api/analyze/sample") && method.equals("POST")) {
                analyzeSample(x);
                return;
            }
            if (path.equals("/api/reports/latest") && method.equals("GET")) {
                AnalysisResult a = latest.get();
                if (a == null) {
                    json(x, 404, error("NO_REPORT", "No report is available. Run an analysis first."));
                    return;
                }
                json(x, 200, a);
                return;
            }
            if (path.equals("/api/reports/latest.csv") && method.equals("GET")) {
                AnalysisResult a = latest.get();
                if (a == null) {
                    json(x, 404, error("NO_REPORT", "No report is available. Run an analysis first."));
                    return;
                }
                x.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"netsentry-alerts.csv\"");
                send(x, 200, reports.alertsAsCsv(a.alerts), "text/csv; charset=utf-8");
                return;
            }
            json(x, 404, error("NOT_FOUND", "Unknown API endpoint."));
        } catch (RequestTooLarge ex) {
            json(x, 413, error("PAYLOAD_TOO_LARGE", ex.getMessage()));
        } catch (IllegalArgumentException ex) {
            json(x, 400, error("INVALID_REQUEST", clean(ex.getMessage())));
        } catch (IOException ex) {
            String message = clean(ex.getMessage());
            int status = message.startsWith("Unsupported file extension") ? 415 : 400;
            json(x, status, error("INPUT_ERROR", message));
        } catch (Exception ex) {
            ex.printStackTrace(System.err);
            json(x, 500, error("INTERNAL_ERROR", "The request could not be completed. Check the server console."));
        }
    }

    private void createIncident(HttpExchange x) throws IOException {
        JsonNode node = Json.mapper().readTree(readLimited(x.getRequestBody()));
        String alertId = textField(node, "alertId");
        if (alertId == null || alertId.isBlank())
            throw new IllegalArgumentException("alertId is required.");
        AnalysisResult result = latest.get();
        if (result == null)
            throw new IllegalArgumentException("Analyze a dataset before creating an incident.");
        Alert alert = result.alerts.stream().filter(a -> alertId.equals(a.id)).findFirst().orElse(null);
        if (alert == null)
            throw new IllegalArgumentException(
                    "The alert was not found in the latest analysis. Run the analysis again if needed.");
        Incident incident = incidents.create(alert, textField(node, "title"));
        json(x, 201, incident);
    }

    private static String textField(JsonNode node, String field) {
        if (node == null || node.get(field) == null || node.get(field).isNull())
            return null;
        return node.get(field).asText();
    }

    private void analyzeUpload(HttpExchange x) throws IOException {
        Map<String, String> query = query(x);
        String filename = query.get("filename");
        if (filename == null || filename.isBlank())
            filename = x.getRequestHeaders().getFirst("Content-Type") != null
                    && x.getRequestHeaders().getFirst("Content-Type").toLowerCase(Locale.ROOT).contains("json")
                            ? "upload.json"
                            : "upload.csv";
        if (!(filename.toLowerCase(Locale.ROOT).endsWith(".csv")
                || filename.toLowerCase(Locale.ROOT).endsWith(".json")))
            throw new IllegalArgumentException("filename must end with .csv or .json");
        byte[] body = readLimited(x.getRequestBody());
        ParseResult parsed = parser.parse(body, filename);
        AnalysisResult result = engine.analyze(parsed, filename, config);
        history.save(result);
        latest.set(result);
        json(x, 200, result);
    }

    private void analyzeSample(HttpExchange x) throws IOException {
        byte[] body = readLimited(x.getRequestBody());
        JsonNode node = body.length == 0 ? null : Json.mapper().readTree(body);
        String sample = node == null || node.get("sample") == null ? null : node.get("sample").asText();
        if (sample == null || SAMPLE_LIST.stream().noneMatch(s -> sample.equals(s.get("name"))))
            throw new IllegalArgumentException("Choose a sample name returned by GET /api/samples");
        try (InputStream in = ApiServer.class.getResourceAsStream("/samples/" + sample)) {
            if (in == null)
                throw new IOException("Bundled sample is missing: " + sample);
            byte[] data = readLimited(in);
            ParseResult parsed = parser.parse(data, sample);
            AnalysisResult result = engine.analyze(parsed, "sample: " + sample, config);
            history.save(result);
            latest.set(result);
            json(x, 200, result);
        }
    }

    private void sendAlerts(HttpExchange x) throws IOException {
        AnalysisResult a = latest.get();
        if (a == null) {
            json(x, 200, List.of());
            return;
        }
        Map<String, String> q = query(x);
        String severity = q.getOrDefault("severity", "").toUpperCase(Locale.ROOT);
        String rule = q.getOrDefault("rule", "").toLowerCase(Locale.ROOT);
        String ip = q.getOrDefault("ip", "").toLowerCase(Locale.ROOT);
        List<Alert> selected = a.alerts.stream().filter(v -> severity.isBlank() || v.severity.equals(severity))
                .filter(v -> rule.isBlank() || v.ruleName.toLowerCase(Locale.ROOT).contains(rule))
                .filter(v -> ip.isBlank() || (v.srcIp != null && v.srcIp.toLowerCase(Locale.ROOT).contains(ip))
                        || (v.dstIp != null && v.dstIp.toLowerCase(Locale.ROOT).contains(ip)))
                .toList();
        json(x, 200, selected);
    }

    private void handleStatic(HttpExchange x) throws IOException {
        addCors(x);
        if (!x.getRequestMethod().equalsIgnoreCase("GET") && !x.getRequestMethod().equalsIgnoreCase("HEAD")) {
            json(x, 405, error("METHOD_NOT_ALLOWED", "Only GET is supported for static assets."));
            return;
        }
        String p = x.getRequestURI().getPath();
        if (p.equals("/"))
            p = "/index.html";
        if (p.contains("..") || p.contains("\\") || p.contains("%2e")) {
            send(x, 400, "Bad path", "text/plain; charset=utf-8");
            return;
        }
        String resource = "/web" + p;
        try (InputStream in = ApiServer.class.getResourceAsStream(resource)) {
            if (in == null) {
                send(x, 404, "Not found", "text/plain; charset=utf-8");
                return;
            }
            byte[] bytes = in.readAllBytes();
            x.getResponseHeaders().set("Cache-Control", "no-store");
            if (x.getRequestMethod().equalsIgnoreCase("HEAD")) {
                x.getResponseHeaders().set("Content-Type", mime(p));
                x.sendResponseHeaders(200, -1);
                x.close();
            } else
                sendBytes(x, 200, bytes, mime(p));
        }
    }

    private static byte[] readLimited(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = in.read(buffer)) != -1) {
            if ((long) out.size() + n > MAX_BODY)
                throw new RequestTooLarge("Request body exceeds the 10 MiB limit");
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    private static Map<String, String> query(HttpExchange x) {
        Map<String, String> map = new LinkedHashMap<>();
        String q = x.getRequestURI().getRawQuery();
        if (q == null)
            return map;
        for (String part : q.split("&")) {
            String[] kv = part.split("=", 2);
            try {
                map.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                        kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
            } catch (Exception ignored) {
            }
        }
        return map;
    }

    private static void addCors(HttpExchange x) {
        String origin = x.getRequestHeaders().getFirst("Origin");
        if (origin != null && (origin.matches("https?://(localhost|127\\.0\\.0\\.1)(:\\d+)?"))) {
            x.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
            x.getResponseHeaders().set("Vary", "Origin");
        }
        x.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        x.getResponseHeaders().set("X-Frame-Options", "DENY");
        x.getResponseHeaders().set("Referrer-Policy", "no-referrer");
    }

    private static void json(HttpExchange x, int status, Object value) throws IOException {
        send(x, status, Json.mapper().writeValueAsString(value), "application/json; charset=utf-8");
    }

    private static Map<String, Object> error(String code, String message) {
        return Map.of("status", "error", "code", code, "message", message == null ? "Request failed" : message);
    }

    private static String clean(String msg) {
        return msg == null ? "Request failed" : msg;
    }

    private static void send(HttpExchange x, int status, String body, String contentType) throws IOException {
        sendBytes(x, status, body.getBytes(StandardCharsets.UTF_8), contentType);
    }

    private static void sendBytes(HttpExchange x, int status, byte[] body, String contentType) throws IOException {
        Headers h = x.getResponseHeaders();
        h.set("Content-Type", contentType);
        h.set("Cache-Control", "no-store");
        x.sendResponseHeaders(status, status == 204 ? -1 : body.length);
        if (status != 204)
            x.getResponseBody().write(body);
        x.close();
    }

    private static String mime(String path) {
        if (path.endsWith(".html"))
            return "text/html; charset=utf-8";
        if (path.endsWith(".css"))
            return "text/css; charset=utf-8";
        if (path.endsWith(".js"))
            return "application/javascript; charset=utf-8";
        if (path.endsWith(".svg"))
            return "image/svg+xml";
        return "application/octet-stream";
    }

    private static Map<String, String> sample(String name, String description) {
        return Map.of("name", name, "description", description, "format", name.endsWith(".json") ? "JSON" : "CSV",
                "synthetic", "true");
    }

    private static final class RequestTooLarge extends IOException {
        RequestTooLarge(String message) {
            super(message);
        }
    }
}