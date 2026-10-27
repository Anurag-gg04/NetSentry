package com.netsentry.detection;

import com.netsentry.config.RuleSettings;
import com.netsentry.model.Alert;
import com.netsentry.model.FlowRecord;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Detects a source contacting many distinct destination hosts in a sliding time window. */
public final class HostSweepRule implements DetectionRule {

    @Override public String name() {
        return "Host Sweep Detection";
    }

    @Override public List<Alert> detect(List<FlowRecord> records, RuleSettings settings, Set<String> allowlist) {
        Map<String, List<FlowRecord>> bySource = new LinkedHashMap<>();
        for (FlowRecord record : RuleSupport.sorted(records)) {
            if (record.srcIp == null || record.dstIp == null || record.eventTime == null) continue;
            if (RuleSupport.excluded(record, allowlist)) continue;
            bySource.computeIfAbsent(record.srcIp, ignored -> new ArrayList<>()).add(record);
        }
        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<FlowRecord>> entry : bySource.entrySet()) {
            List<FlowRecord> flows = entry.getValue();
            Map<String, Integer> targetCounts = new LinkedHashMap<>();
            int left = 0, maxHosts = 0;
            Instant bestStart = flows.get(0).eventTime, bestEnd = bestStart;
            for (int right = 0; right < flows.size(); right++) {
                FlowRecord current = flows.get(right);
                targetCounts.merge(current.dstIp, 1, Integer::sum);
                while (left <= right && Duration.between(flows.get(left).eventTime, current.eventTime).getSeconds() > settings.windowSeconds) {
                    String oldTarget = flows.get(left++).dstIp;
                    targetCounts.computeIfPresent(oldTarget, (key, count) -> count == 1 ? null : count - 1);
                }
                if (targetCounts.size() > maxHosts) {
                    maxHosts = targetCounts.size();
                    bestStart = flows.get(left).eventTime;
                    bestEnd = current.eventTime;
                }
            }
            if (maxHosts >= settings.threshold) {
                alerts.add(RuleSupport.alert(name(), settings.severity, entry.getKey(), null, bestStart, bestEnd, maxHosts, settings.threshold, "distinct destination hosts", "Source contacted " + maxHosts + " distinct destination hosts within " + settings.windowSeconds + " seconds. This can indicate host discovery, but may also reflect legitimate inventory or monitoring activity.", List.of("Check whether the source is an approved discovery or monitoring tool.", "Review destination systems and connection outcomes during the reported window.", "Validate the activity before applying blocks or other disruptive controls.")));
            }
        }
        return alerts;
    }
}
