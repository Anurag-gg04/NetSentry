package com.netsentry.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AnalysisResult {
    public String status = "completed";
    public String datasetName;
    public String analysisTimestamp;
    public long durationMs;
    public long totalRecords;
    public long acceptedRecords;
    public long rejectedRecords;
    public double recordsPerSecond;
    public int alertCount;
    public Map<String, Integer> severityCounts = new LinkedHashMap<>();
    public List<Alert> alerts = new ArrayList<>();
    public List<String> validationErrors = new ArrayList<>();
    public List<TrendPoint> trafficTrend = new ArrayList<>();
    public Object rulesUsed;

    public static class TrendPoint {
        public String bucket;
        public long connections;
        public long bytes;

        public TrendPoint() {
        }

        public TrendPoint(String bucket, long connections, long bytes) {
            this.bucket = bucket;
            this.connections = connections;
            this.bytes = bytes;
        }
    }
}
