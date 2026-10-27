package com.netsentry.detection;

import com.netsentry.config.RuleSettings;
import com.netsentry.model.Alert;
import com.netsentry.model.FlowRecord;
import java.util.List;
import java.util.Set;

public interface DetectionRule {
    String name();
    List<Alert> detect(List<FlowRecord> records, RuleSettings settings, Set<String> allowlist);
}
