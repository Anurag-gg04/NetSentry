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

public class ConnectionBurstRule implements DetectionRule {

    @Override public String name() {
        return "Connection Burst Detection";
    }

    @Override public List<Alert> detect(List<FlowRecord> records, RuleSettings s, Set<String> allowlist) {
        Map<String, List<FlowRecord>> groups = new LinkedHashMap<>();
        for (FlowRecord r : RuleSupport.sorted(records)) if (!RuleSupport.excluded(r, allowlist)) groups.computeIfAbsent(r.srcIp, k -> new ArrayList<>()).add(r);
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
            if (max >= s.threshold) out.add(RuleSupport.alert(name(), s.severity, entry.getKey(), null, bestStart, bestEnd, max, s.threshold, "connection attempts", "Source generated " + max + " flow records in a " + s.windowSeconds + "-second window. A burst may reflect automation or a sudden legitimate workload.", List.of("Correlate the source with authentication and application logs.", "Check whether the burst matches a load test or scheduled job.", "Use upstream rate limiting if the traffic is unapproved.")));
        }
        return out;
    }
}
