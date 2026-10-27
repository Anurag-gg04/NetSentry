package com.netsentry.config;

import java.util.Locale;
import java.util.Set;

public class RuleSettings {
    public boolean enabled = true;
    public int threshold = 10;
    public int windowSeconds = 60;
    public String severity = "MEDIUM";
    public int bucketSeconds = 60;
    public double baselineMultiplier = 2.0;

    public RuleSettings() {
    }

    public RuleSettings(boolean enabled, int threshold, int windowSeconds, String severity) {
        this.enabled = enabled;
        this.threshold = threshold;
        this.windowSeconds = windowSeconds;
        this.severity = severity;
    }

    public void validate(String ruleName) {
        if (threshold < 1) throw new IllegalArgumentException(ruleName + ".threshold must be at least 1");
        if (windowSeconds < 1 || windowSeconds > 86400) throw new IllegalArgumentException(ruleName + ".windowSeconds must be in 1..86400");
        if (severity == null || !Set.of("HIGH", "MEDIUM", "LOW").contains(severity.toUpperCase(Locale.ROOT))) throw new IllegalArgumentException(ruleName + ".severity must be HIGH, MEDIUM, or LOW");
        severity = severity.toUpperCase(Locale.ROOT);
        if (bucketSeconds < 1 || bucketSeconds > 86400) throw new IllegalArgumentException(ruleName + ".bucketSeconds must be in 1..86400");
        if (!Double.isFinite(baselineMultiplier) || baselineMultiplier <= 1.0 || baselineMultiplier > 1000.0) throw new IllegalArgumentException(ruleName + ".baselineMultiplier must be greater than 1 and at most 1000");
    }
}
