package com.netsentry.detection;

import com.netsentry.config.RuleSettings;
import com.netsentry.config.RulesConfig;
import com.netsentry.ingestion.ParseResult;
import com.netsentry.model.Alert;
import com.netsentry.model.AnalysisResult;
import com.netsentry.model.FlowRecord;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeMap;

public class DetectionEngine {
    private final List<DetectionRule> rules = List.of(new PortScanRule(), new ConnectionBurstRule(), new FailedConnectionsRule(), new TrafficSpikeRule(), new HostSweepRule());
    private final AlertDeduplicator deduplicator = new AlertDeduplicator();

    public AnalysisResult analyze(ParseResult input, String datasetName, RulesConfig config) {
        long started = System.nanoTime();
        config.validate();
        List<FlowRecord> records = new ArrayList<>(input.records);
        records.sort(Comparator.comparing(r -> r.eventTime));
        Set<String> allowlist = new HashSet<>();
        for (String ip : config.allowlist) allowlist.add(ip.toLowerCase(Locale.ROOT));
        List<Alert> all = new ArrayList<>();
        run(new PortScanRule(), records, config.portScan, allowlist, all);
        run(new ConnectionBurstRule(), records, config.connectionBurst, allowlist, all);
        run(new FailedConnectionsRule(), records, config.failedConnections, allowlist, all);
        run(new TrafficSpikeRule(), records, config.trafficSpike, allowlist, all);
        run(new HostSweepRule(), records, config.hostSweep, allowlist, all);
        List<Alert> deduped = deduplicator.deduplicate(all, config.deduplicationWindowSeconds);
        deduped.sort(Comparator.comparing((Alert a) -> a.detectionTimestamp).reversed());
        AnalysisResult result = new AnalysisResult();
        result.datasetName = datasetName;
        result.analysisTimestamp = Instant.now().toString();
        result.totalRecords = input.totalRows;
        result.acceptedRecords = input.records.size();
        result.rejectedRecords = input.rejectedRows;
        result.validationErrors = input.errors;
        result.alerts = deduped;
        result.alertCount = deduped.size();
        result.rulesUsed = config;
        result.severityCounts.put("HIGH", 0);
        result.severityCounts.put("MEDIUM", 0);
        result.severityCounts.put("LOW", 0);
        for (Alert alert : deduped) result.severityCounts.compute(alert.severity, (k, v) -> v == null ? 1 : v + 1);
        TreeMap<Long, long[]> trend = new TreeMap<>();
        for (FlowRecord r : records) {
            long bucket = Math.floorDiv(r.eventTime.getEpochSecond(), 60) * 60;
            long[] m = trend.computeIfAbsent(bucket, k -> new long[2]);
            m[0]++;
            m[1] += r.bytes == null ? 0 : r.bytes;
        }
        trend.forEach((time, m) -> result.trafficTrend.add(new AnalysisResult.TrendPoint(Instant.ofEpochSecond(time).toString(), m[0], m[1])));
        result.durationMs = Math.max(0, (System.nanoTime() - started) / 1_000_000);
        result.recordsPerSecond = result.durationMs == 0 ? 0 : result.acceptedRecords * 1000.0 / result.durationMs;
        return result;
    }

    private static void run(DetectionRule rule, List<FlowRecord> records, RuleSettings settings, Set<String> allowlist, List<Alert> into) {
        if (settings.enabled) into.addAll(rule.detect(records, settings, allowlist));
    }

    public List<DetectionRule> availableRules() {
        return rules;
    }
}
