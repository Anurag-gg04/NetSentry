package com.netsentry.detection;

import com.netsentry.model.Alert;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AlertDeduplicator {

    public List<Alert> deduplicate(List<Alert> input, int windowSeconds) {
        Map<String, Alert> unique = new LinkedHashMap<>();
        for (Alert a : input) {
            long epoch;
            try {
                epoch = Instant.parse(a.detectionTimestamp).getEpochSecond();
            } catch (Exception ex) {
                epoch = 0;
            }
            String bucket = Long.toString(Math.floorDiv(epoch, windowSeconds));
            String key = a.ruleName + "|" + a.srcIp + "|" + a.dstIp + "|" + bucket;
            Alert previous = unique.get(key);
            if (previous == null) unique.put(key, a);
            else if (a.observedMetric > previous.observedMetric) unique.put(key, a);
        }
        return new ArrayList<>(unique.values());
    }
}
