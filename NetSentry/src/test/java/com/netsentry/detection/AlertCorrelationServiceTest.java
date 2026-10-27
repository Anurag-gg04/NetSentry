package com.netsentry.detection;

import com.netsentry.model.Alert;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class AlertCorrelationServiceTest {
    private final AlertCorrelationService service = new AlertCorrelationService();

    @Test void correlatesDifferentRulesFromSameSourceWithinTenMinutes() {
        Alert first = alert("Port Scan Detection", "HIGH", "203.0.113.8", "2026-10-27T10:00:00Z");
        Alert second = alert("Host Sweep Detection", "MEDIUM", "203.0.113.8", "2026-10-27T10:06:00Z");
        var result = service.correlate(List.of(first, second));
        assertEquals(1, result.size());
        assertEquals("203.0.113.8", result.get(0).sourceIp);
        assertEquals(2, result.get(0).alertCount);
        assertEquals(2, result.get(0).distinctRuleCount);
        assertEquals("HIGH", result.get(0).severity);
    }

    @Test void doesNotCorrelateSameRuleOnlyOrEventsOutsideWindow() {
        assertTrue(service.correlate(List.of( alert("Port Scan Detection", "HIGH", "203.0.113.8", "2026-10-27T10:00:00Z"), alert("Port Scan Detection", "HIGH", "203.0.113.8", "2026-10-27T10:01:00Z"))).isEmpty());
        assertTrue(service.correlate(List.of( alert("Port Scan Detection", "HIGH", "203.0.113.8", "2026-10-27T10:00:00Z"), alert("Host Sweep Detection", "MEDIUM", "203.0.113.8", "2026-10-27T10:20:00Z"))).isEmpty());
    }

    @Test void ignoresAlertsWithoutSourceAndHandlesNullInput() {
        Alert noSource = alert("Rule A", "LOW", null, "2026-10-27T10:00:00Z");
        assertTrue(service.correlate(List.of(noSource)).isEmpty());
        assertTrue(service.correlate(null).isEmpty());
    }

    private static Alert alert(String rule, String severity, String src, String timestamp) {
        Alert alert = new Alert();
        alert.id = java.util.UUID.randomUUID().toString();
        alert.ruleName = rule;
        alert.severity = severity;
        alert.srcIp = src;
        alert.detectionTimestamp = timestamp;
        return alert;
    }
}
