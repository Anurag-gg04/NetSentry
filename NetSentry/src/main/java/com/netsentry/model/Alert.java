package com.netsentry.model;

import java.util.ArrayList;
import java.util.List;

public class Alert {
    public String id;
    public String ruleName;
    public String severity;
    public String srcIp;
    public String dstIp;
    public String detectionTimestamp;
    public String windowStart;
    public String windowEnd;
    public double observedMetric;
    public double configuredThreshold;
    public String metricName;
    public String explanation;
    public List<String> recommendations = new ArrayList<>();

    public Alert() {
    }

    public Alert(String ruleName, String severity, String srcIp, String dstIp, String detectionTimestamp, String windowStart, String windowEnd, double observedMetric, double configuredThreshold, String metricName, String explanation, List<String> recommendations) {
        this.id = java.util.UUID.randomUUID().toString();
        this.ruleName = ruleName;
        this.severity = severity;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.detectionTimestamp = detectionTimestamp;
        this.windowStart = windowStart;
        this.windowEnd = windowEnd;
        this.observedMetric = observedMetric;
        this.configuredThreshold = configuredThreshold;
        this.metricName = metricName;
        this.explanation = explanation;
        this.recommendations = recommendations == null ? new ArrayList<>() : recommendations;
    }
}
