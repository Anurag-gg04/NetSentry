package com.netsentry.detection;

import com.netsentry.model.Alert;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Groups alerts from one source when different rules trigger within ten minutes. */
public class AlertCorrelationService {
    public static final long DEFAULT_WINDOW_MINUTES = 10;

    public List<Correlation> correlate(List<Alert> alerts) {
        Map<String, List<Alert>> bySource = new LinkedHashMap<>();
        if (alerts == null) return List.of();
        for (Alert alert : alerts) {
            if (alert == null || alert.srcIp == null || alert.srcIp.isBlank()) continue;
            bySource.computeIfAbsent(alert.srcIp, ignored -> new ArrayList<>()).add(alert);
        }
        List<Correlation> results = new ArrayList<>();
        for (Map.Entry<String, List<Alert>> entry : bySource.entrySet()) {
            List<Alert> sourceAlerts = entry.getValue();
            sourceAlerts.sort(Comparator.comparing(AlertCorrelationService::timestamp, Comparator.nullsLast(Comparator.naturalOrder())));
            List<Alert> window = new ArrayList<>();
            for (Alert candidate : sourceAlerts) {
                Instant time = timestamp(candidate);
                if (time == null) continue;
                window.removeIf(existing -> {
                    Instant existingTime = timestamp(existing);
                    return existingTime != null && existingTime.isBefore(time.minus(DEFAULT_WINDOW_MINUTES, ChronoUnit.MINUTES));
                });
                window.add(candidate);
                Correlation correlation = build(entry.getKey(), window);
                if (correlation != null) results.add(correlation);
            }
        }
        // A source can produce multiple rolling windows; retain the broadest useful summary per source.
        Map<String, Correlation> bestBySource = new LinkedHashMap<>();
        for (Correlation item : results) {
            Correlation previous = bestBySource.get(item.sourceIp);
            if (previous == null || item.alertCount > previous.alertCount || (item.alertCount == previous.alertCount && item.distinctRuleCount > previous.distinctRuleCount)) {
                bestBySource.put(item.sourceIp, item);
            }
        }
        return bestBySource.values().stream().sorted(Comparator.comparingInt((Correlation c) -> severityRank(c.severity)).reversed().thenComparing(Comparator.comparingInt((Correlation c) -> c.alertCount).reversed())).toList();
    }

    private static Correlation build(String sourceIp, List<Alert> alerts) {
        Set<String> rules = new LinkedHashSet<>();
        Set<String> ids = new LinkedHashSet<>();
        String severity = "LOW";
        Instant first = null, last = null;
        for (Alert alert : alerts) {
            if (alert.ruleName != null) rules.add(alert.ruleName);
            if (alert.id != null) ids.add(alert.id);
            if (severityRank(alert.severity) > severityRank(severity)) severity = alert.severity;
            Instant t = timestamp(alert);
            if (t != null && (first == null || t.isBefore(first))) first = t;
            if (t != null && (last == null || t.isAfter(last))) last = t;
        }
        if (rules.size() < 2) return null;
        Correlation result = new Correlation();
        result.id = sourceIp;
        result.sourceIp = sourceIp;
        result.alertCount = ids.size();
        result.distinctRuleCount = rules.size();
        result.severity = severity;
        result.firstSeen = first == null ? null : first.toString();
        result.lastSeen = last == null ? null : last.toString();
        result.ruleNames = List.copyOf(rules);
        result.alertIds = List.copyOf(ids);
        result.summary = "One source triggered " + rules.size() + " different detection rules within a " + DEFAULT_WINDOW_MINUTES + "-minute correlation window.";
        result.recommendedAction = "Review the source host, validate the individual alert evidence, and check authorized network or endpoint logs before deciding whether this is malicious.";
        return result;
    }

    private static Instant timestamp(Alert alert) {
        if (alert == null || alert.detectionTimestamp == null) return null;
        try {
            return Instant.parse(alert.detectionTimestamp);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static int severityRank(String severity) {
        if (severity == null) return 0;
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }

    public static class Correlation {
        public String id;
        public String sourceIp;
        public int alertCount;
        public int distinctRuleCount;
        public String severity;
        public String firstSeen;
        public String lastSeen;
        public List<String> ruleNames = List.of();
        public List<String> alertIds = List.of();
        public String summary;
        public String recommendedAction;
    }
}
