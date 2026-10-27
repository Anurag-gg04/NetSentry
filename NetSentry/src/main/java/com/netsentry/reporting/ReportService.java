package com.netsentry.reporting;

import com.netsentry.model.Alert;
import com.netsentry.model.AnalysisResult;
import com.netsentry.util.Json;
import java.io.IOException;
import java.util.List;

public class ReportService {

    public String asJson(AnalysisResult result) throws IOException {
        return Json.mapper().writeValueAsString(result);
    }

    public String alertsAsCsv(List<Alert> alerts) {
        StringBuilder out = new StringBuilder(
                "id,ruleName,severity,srcIp,dstIp,detectionTimestamp,windowStart,windowEnd,metricName,observedMetric,configuredThreshold,explanation\n");
        for (Alert a : alerts) {
            out.append(row(a.id)).append(',').append(row(a.ruleName)).append(',').append(row(a.severity)).append(',')
                    .append(row(a.srcIp)).append(',').append(row(a.dstIp)).append(',').append(row(a.detectionTimestamp))
                    .append(',').append(row(a.windowStart)).append(',').append(row(a.windowEnd)).append(',')
                    .append(row(a.metricName)).append(',').append(a.observedMetric).append(',')
                    .append(a.configuredThreshold).append(',').append(row(a.explanation)).append('\n');
        }
        return out.toString();
    }

    private static String row(String input) {
        if (input == null)
            return "";
        return "\"" + input.replace("\"", "\"\"").replace("\r", " ").replace("\n", " ") + "\"";
    }
}
