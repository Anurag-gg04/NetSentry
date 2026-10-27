package com.netsentry.detection;

import com.netsentry.config.RuleSettings;
import com.netsentry.model.Alert;
import com.netsentry.model.FlowRecord;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PortScanRule implements DetectionRule {

    @Override public String name() {
        return "Port Scan Detection";
    }

    @Override public List<Alert> detect(List<FlowRecord> records, RuleSettings s, Set<String> allowlist) {
        Map<String, List<FlowRecord>> groups = new LinkedHashMap<>();
        for (FlowRecord r : RuleSupport.sorted(records)) {
            if (RuleSupport.excluded(r, allowlist)) continue;
            groups.computeIfAbsent(r.getSourceKey(), k -> new ArrayList<>()).add(r);
        }
        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<FlowRecord>> entry : groups.entrySet()) {
            List<FlowRecord> group = entry.getValue();
            Map<Integer, Integer> portCounts = new HashMap<>();
            int left = 0, maxPorts = 0;
            Instant bestStart = group.get(0).eventTime, bestEnd = bestStart;
            for (int right = 0; right < group.size(); right++) {
                FlowRecord current = group.get(right);
                portCounts.merge(current.dstPort, 1, Integer::sum);
                while (left <= right && Duration.between(group.get(left).eventTime, current.eventTime).compareTo(Duration.ofSeconds(s.windowSeconds)) > 0) {
                    int p = group.get(left).dstPort;
                    portCounts.computeIfPresent(p, (k, v) -> v == 1 ? null : v - 1);
                    left++;
                }
                if (portCounts.size() > maxPorts) {
                    maxPorts = portCounts.size();
                    bestStart = group.get(left).eventTime;
                    bestEnd = current.eventTime;
                }
            }
            if (maxPorts >= s.threshold) {
                String[] pair = entry.getKey().split("->", 2);
                alerts.add(RuleSupport.alert(name(), s.severity, pair[0], pair[1], bestStart, bestEnd, maxPorts, s.threshold, "distinct destination ports", "Source contacted " + maxPorts + " distinct destination ports on the same target within " + s.windowSeconds + " seconds. This pattern can indicate port discovery, but can also occur during legitimate service checks.", List.of("Confirm whether the source is an approved scanner or monitoring host.", "Review firewall and service logs for the target during the window.", "Apply rate limits or temporary blocks only after validating business impact.")));
            }
        }
        return alerts;
    }
}
