package com.netsentry.incidents;

import com.netsentry.model.Alert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class IncidentServiceTest {
    @TempDir Path temp;

    @Test void createUpdateListAndDeleteIncident() throws Exception {
        IncidentService service = new IncidentService(temp.resolve("incidents"));
        Alert alert = new Alert("Port Scan Detection", "HIGH", "198.51.100.8", "192.0.2.10", "2026-10-28T10:00:00Z", "2026-10-28T09:59:00Z", "2026-10-28T10:00:00Z", 20, 10, "unique ports", "Many ports", List.of("Review firewall logs"));
        Incident created = service.create(alert, null);
        assertEquals("OPEN", created.status);
        assertEquals(alert.id, created.alertId);
        Incident updated = service.update(created.id, "INVESTIGATING", "Analyst A", "Checked firewall logs.");
        assertEquals("INVESTIGATING", updated.status);
        assertEquals("Analyst A", updated.assignedTo);
        assertEquals("Checked firewall logs.", updated.notes);
        assertEquals(1, service.list().size());
        assertNotNull(service.get(created.id));
        assertTrue(service.delete(created.id));
        assertNull(service.get(created.id));
    }

    @Test void rejectsUnknownStatusAndMalformedId() throws Exception {
        IncidentService service = new IncidentService(temp.resolve("incidents"));
        Alert alert = new Alert("Test", "LOW", "198.51.100.1", "192.0.2.1", "2026-10-28T10:00:00Z", "", "", 1, 1, "count", "test", List.of());
        Incident incident = service.create(alert, "Test case");
        assertThrows(IllegalArgumentException.class, () -> service.update(incident.id, "MAYBE", null, null));
        assertThrows(IllegalArgumentException.class, () -> service.get("not-an-id"));
    }
}
