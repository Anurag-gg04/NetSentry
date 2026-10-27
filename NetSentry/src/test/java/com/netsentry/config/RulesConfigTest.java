package com.netsentry.config;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RulesConfigTest {

    @Test void acceptsDefaultConfig() {
        assertDoesNotThrow(() -> new RulesConfig().validate());
    }

    @Test void rejectsInvalidHostSweepThreshold() {
        RulesConfig c=new RulesConfig();
        c.hostSweep.threshold=0;
        assertThrows(IllegalArgumentException.class, c::validate);
    }

    @Test void rejectsNegativeThreshold() {
        RulesConfig c=new RulesConfig();
        c.portScan.threshold=-1;
        assertThrows(IllegalArgumentException.class, c::validate);
    }

    @Test void rejectsUnknownSeverity() {
        RulesConfig c=new RulesConfig();
        c.failedConnections.severity="CRITICAL";
        assertThrows(IllegalArgumentException.class, c::validate);
    }

    @Test void rejectsMalformedAllowlistIp() {
        RulesConfig c=new RulesConfig();
        c.allowlist.add("999.1.1.1");
        assertThrows(IllegalArgumentException.class, c::validate);
    }

    @Test void rejectsBadBaselineMultiplier() {
        RulesConfig c=new RulesConfig();
        c.trafficSpike.baselineMultiplier=1;
        assertThrows(IllegalArgumentException.class, c::validate);
    }
}
