package com.netsentry.reporting;

import com.netsentry.model.Alert;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ReportServiceTest {

    @Test void csvReportHasHeaderAndEscapesCommasAndQuotes() {
        Alert alert = new Alert("Port Scan, Detection", "HIGH", "198.51.100.1", "192.0.2.1", "2026-10-27T10:00:00Z", "2026-10-27T10:00:00Z", "2026-10-27T10:00:20Z", 10, 8, "distinct ports", "A \"quoted\" explanation", List.of("Review logs"));
        String csv = new ReportService().alertsAsCsv(List.of(alert));
        assertTrue(csv.startsWith("id,ruleName,severity"));
        assertTrue(csv.contains("\"Port Scan, Detection\""));
        assertTrue(csv.contains("\"A \"\"quoted\"\" explanation\""));
    }

    @Test void emptyAlertListStillProducesHeader() {
        String csv = new ReportService().alertsAsCsv(List.of());
        assertEquals(1, csv.lines().count());
    }
}
