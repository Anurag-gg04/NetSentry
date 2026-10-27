package com.netsentry.detection;

import com.netsentry.model.Alert;
import com.netsentry.model.FlowRecord;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

final class RuleSupport {

    private RuleSupport() {
    }
    static List<FlowRecord> sorted(List<FlowRecord> records) {
        List<FlowRecord> copy = new ArrayList<>(records);
        copy.sort(Comparator.comparing(r -> r.eventTime));
        return copy;
    }
    static boolean excluded(FlowRecord r, Set<String> allowlist) {
        return allowlist.contains(r.srcIp.toLowerCase(java.util.Locale.ROOT));
    }
    static String time(Instant instant) {
        return instant.toString();
    }
    static Alert alert(String rule, String severity, String src, String dst, Instant start, Instant end, double metric, double threshold, String metricName, String explanation, List<String> advice) {
        return new Alert(rule, severity, src, dst, time(end), time(start), time(end), metric, threshold, metricName, explanation, advice);
    }
}
