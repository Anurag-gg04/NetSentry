package com.netsentry.history;

import com.netsentry.model.AnalysisResult;
import java.util.LinkedHashMap;
import java.util.Map;

/** Summary fields saved for a completed analysis; input rows are not retained. */
public class AnalysisHistoryEntry {
    public String id;
    public String timestamp;
    public String datasetName;
    public long totalRecords;
    public long acceptedRecords;
    public long rejectedRecords;
    public int alertCount;
    public long durationMs;
    public Map<String, Integer> severityCounts = new LinkedHashMap<>();

    public AnalysisHistoryEntry() {
    }

    public static AnalysisHistoryEntry from(AnalysisResult result) {
        AnalysisHistoryEntry entry = new AnalysisHistoryEntry();
        entry.id = java.util.UUID.randomUUID().toString();
        entry.timestamp = result.analysisTimestamp;
        entry.datasetName = result.datasetName;
        entry.totalRecords = result.totalRecords;
        entry.acceptedRecords = result.acceptedRecords;
        entry.rejectedRecords = result.rejectedRecords;
        entry.alertCount = result.alertCount;
        entry.durationMs = result.durationMs;
        entry.severityCounts.putAll(result.severityCounts);
        return entry;
    }
}
