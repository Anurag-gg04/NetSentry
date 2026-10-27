package com.netsentry.detection;

import com.netsentry.config.RuleSettings;
import com.netsentry.model.Alert;
import com.netsentry.model.FlowRecord;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class TrafficSpikeRule implements DetectionRule {

    @Override public String name() {
        return "Traffic Spike Detection";
    }

    @Override public List<Alert> detect(List<FlowRecord> records, RuleSettings s, Set<String> allowlist) {
        TreeMap<Long, List<FlowRecord>> buckets = new TreeMap<>();
        for (FlowRecord r : records) if (!RuleSupport.excluded(r, allowlist)) {
            long bucket = Math.floorDiv(r.eventTime.getEpochSecond(), s.bucketSeconds);
            buckets.computeIfAbsent(bucket, k -> new ArrayList<>()).add(r);
        }
        if (buckets.isEmpty()) return List.of();
        // Baseline strategy: median count of the other observed (non-empty) buckets. This avoids
        // inventing zero-traffic intervals across arbitrarily large timestamp gaps.
        List<Long> sortedCounts = new ArrayList<>();
        for (List<FlowRecord> bucketRecords : buckets.values()) sortedCounts.add((long) bucketRecords.size());
        Collections.sort(sortedCounts);
        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<Long, List<FlowRecord>> entry : buckets.entrySet()) {
            long count = entry.getValue().size();
            if (count < s.threshold) continue;
            double baseline = medianWithout(sortedCounts, count);
            double required = Math.max(1.0, baseline * s.baselineMultiplier);
            if (count >= required) {
                Map<String, Integer> bySource = new HashMap<>();
                long totalBytes = 0;
                for (FlowRecord r : entry.getValue()) {
                    bySource.merge(r.srcIp, 1, Integer::sum);
                    totalBytes += r.bytes == null ? 0 : r.bytes;
                }
                String topSource = bySource.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);
                Instant start = Instant.ofEpochSecond(entry.getKey() * s.bucketSeconds), end = Instant.ofEpochSecond((entry.getKey() + 1) * s.bucketSeconds - 1);
                alerts.add(RuleSupport.alert(name(), s.severity, topSource, null, start, end, count, s.threshold, "bucket connection count", "Observed " + count + " flows in a " + s.bucketSeconds + "-second bucket versus a median of other observed buckets of " + baseline + " flows (multiplier " + s.baselineMultiplier + "). Total bucket bytes: " + totalBytes + ". A traffic spike is an anomaly signal, not proof of an attack.", List.of("Compare the interval with expected business traffic and scheduled jobs.", "Inspect top source IPs and byte counts in the source dataset.", "Check network, application, and deployment telemetry before taking action.")));
            }
        }
        return alerts;
    }

    private static double medianWithout(List<Long> sorted, long removed) {
        if (sorted.size() <= 1) return 0;
        int index = Collections.binarySearch(sorted, removed);
        if (index < 0) return median(sorted);
        // O(log n) selection from the sorted population while logically skipping one matching value.
        int peerCount = sorted.size() - 1;
        if (peerCount % 2 == 1) return valueExcept(sorted, index, peerCount / 2);
        return (valueExcept(sorted, index, peerCount / 2 - 1) + valueExcept(sorted, index, peerCount / 2)) / 2.0;
    }

    private static long valueExcept(List<Long> sorted, int removedIndex, int peerIndex) {
        return sorted.get(peerIndex < removedIndex ? peerIndex : peerIndex + 1);
    }

    private static double median(List<Long> sorted) {
        int n = sorted.size();
        if (n == 0) return 0;
        return n % 2 == 1 ? sorted.get(n / 2) : (sorted.get(n / 2 - 1) + sorted.get(n / 2)) / 2.0;
    }
}
