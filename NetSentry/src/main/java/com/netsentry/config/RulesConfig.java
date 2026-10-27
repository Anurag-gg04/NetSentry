package com.netsentry.config;

import com.netsentry.util.IpValidator;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class RulesConfig {
    public List<String> allowlist = new ArrayList<>(List.of("127.0.0.1", "::1"));
    public RuleSettings portScan = new RuleSettings(true, 10, 60, "HIGH");
    public RuleSettings connectionBurst = new RuleSettings(true, 30, 60, "MEDIUM");
    public RuleSettings failedConnections = new RuleSettings(true, 8, 120, "HIGH");
    public RuleSettings trafficSpike = new RuleSettings(true, 20, 60, "MEDIUM");
    public RuleSettings hostSweep = new RuleSettings(true, 12, 60, "MEDIUM");
    public int deduplicationWindowSeconds = 60;

    public void validate() {
        if (portScan == null || connectionBurst == null || failedConnections == null || trafficSpike == null || hostSweep == null) throw new IllegalArgumentException("All five rule configurations must be present");
        portScan.validate("portScan");
        connectionBurst.validate("connectionBurst");
        failedConnections.validate("failedConnections");
        trafficSpike.validate("trafficSpike");
        hostSweep.validate("hostSweep");
        if (deduplicationWindowSeconds < 1 || deduplicationWindowSeconds > 86400) throw new IllegalArgumentException("deduplicationWindowSeconds must be in 1..86400");
        if (allowlist == null) allowlist = new ArrayList<>();
        Set<String> clean = new LinkedHashSet<>();
        for (String ip : allowlist) {
            if (!IpValidator.isValid(ip)) throw new IllegalArgumentException("Invalid IP in allowlist: " + ip);
            clean.add(ip.trim().toLowerCase(Locale.ROOT));
        }
        allowlist = new ArrayList<>(clean);
    }
}
