package com.netsentry.detection;

import com.netsentry.config.RuleSettings;
import com.netsentry.model.Alert;
import com.netsentry.model.FlowRecord;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class FailedConnectionsRule implements DetectionRule {

    @Override public String name() {
        return "Repeated Failed Connections";
    }

    @Override public List<Alert> detect(List<FlowRecord> records, RuleSettings s, Set<String> allowlist) {
        Map<String, List<FlowRecord>> groups = new LinkedHashMap<>();
        for (FlowRecord r : RuleSupport.sorted(records)) {
            if (!RuleSupport.excluded(r, allowlist) && "FAILED".equals(r.connectionStatus)) groups.computeIfAbsent(r.getSourceKey(), k -> new ArrayList<>()).add(r);
        }
        List<Alert> out = new ArrayList<>();
        for (Map.Entry<String, List<FlowRecord>> entry : groups.entrySet()) {
            List<FlowRecord> g = entry.getValue();
            int left = 0, max = 0;
            Instant bestStart = g.get(0).eventTime, bestEnd = bestStart;
            for (int right = 0; right < g.size(); right++) {
                while (left <= right && Duration.between(g.get(left).eventTime, g.get(right).eventTime).compareTo(Duration.ofSeconds(s.windowSeconds)) > 0) left++;
                int count = right - left + 1;
                if (count > max) {
                    max = count;
                    bestStart = g.get(left).eventTime;
                    bestEnd = g.get(right).eventTime;
                }
            }
            if (max >= s.threshold) {
                String[] pair = entry.getKey().split("->", 2);
                out.add(RuleSupport.alert(name(), s.severity, pair[0], pair[1], bestStart, bestEnd, max, s.threshold, "failed connection attempts", "Observed " + max + " FAILED connection records from the source to this target inside " + s.windowSeconds + " seconds. Failed connections can also result from misconfiguration or temporary outages.", List.of("Inspect authentication and service logs for related failures.", "Check for a recent deployment, network change, or expired credentials.", "Escalate or rate-limit only if the activity is unrecognized and corroborated.")));
            }
        }
        return out;
    }
}
