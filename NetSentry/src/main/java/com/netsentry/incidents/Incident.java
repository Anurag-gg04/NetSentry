package com.netsentry.incidents;

import com.netsentry.model.Alert;
import java.time.Instant;
import java.util.UUID;

/** Case details copied from an alert for later triage. */
public class Incident {
    public String id;
    public String alertId;
    public String title;
    public String severity;
    public String srcIp;
    public String dstIp;
    public String ruleName;
    public String explanation;
    public String status;
    public String assignedTo;
    public String notes;
    public String createdAt;
    public String updatedAt;

    public Incident() {
    }

    public static Incident fromAlert(Alert alert, String title) {
        Incident i = new Incident();
        i.id = UUID.randomUUID().toString();
        i.alertId = alert.id;
        i.title = title == null || title.isBlank() ? alert.ruleName + " — " + alert.srcIp : title.trim();
        i.severity = alert.severity;
        i.srcIp = alert.srcIp;
        i.dstIp = alert.dstIp;
        i.ruleName = alert.ruleName;
        i.explanation = alert.explanation;
        i.status = "OPEN";
        i.assignedTo = "Unassigned";
        i.notes = "";
        i.createdAt = Instant.now().toString();
        i.updatedAt = i.createdAt;
        return i;
    }
}
