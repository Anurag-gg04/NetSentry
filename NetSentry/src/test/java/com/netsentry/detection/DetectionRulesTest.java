package com.netsentry.detection;

import com.netsentry.config.RuleSettings;
import com.netsentry.ingestion.ParseResult;
import com.netsentry.model.Alert;
import com.netsentry.model.FlowRecord;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class DetectionRulesTest {

    private FlowRecord flow(int second, String src, String dst, int port, String status) {
        FlowRecord r=new FlowRecord();
        r.eventTime=Instant.parse("2026-10-27T10:00:00Z").plusSeconds(second);
        r.timestamp=r.eventTime.toString();
        r.srcIp=src;
        r.dstIp=dst;
        r.dstPort=port;
        r.srcPort=40000+second;
        r.protocol="TCP";
        r.packets=1L;
        r.bytes=100L;
        r.connectionStatus=status;
        return r;
    }

    @Test void detectsPortScanAndIncludesDistinctPortEvidence() {
        List<FlowRecord> rs=new ArrayList<>();
        for(int i=0; i<10; i++)rs.add(flow(i*2, "198.51.100.1", "192.0.2.1", 20+i, "SUCCESS"));
        RuleSettings s=new RuleSettings(true, 10, 60, "HIGH");
        List<Alert> alerts=new PortScanRule().detect(rs, s, Set.of());
        assertEquals(1, alerts.size());
        assertEquals(10, alerts.get(0).observedMetric);
        assertTrue(alerts.get(0).explanation.contains("10 distinct destination ports"));
    }

    @Test void respectsAllowlistForPortScan() {
        List<FlowRecord> rs=new ArrayList<>();
        for(int i=0; i<12; i++)rs.add(flow(i, "127.0.0.1", "192.0.2.1", 100+i, "SUCCESS"));
        assertTrue(new PortScanRule().detect(rs, new RuleSettings(true, 10, 60, "HIGH"), Set.of("127.0.0.1")).isEmpty());
    }

    @Test void connectionBurstUsesSlidingWindowBoundary() {
        List<FlowRecord> rs=List.of(flow(0, "198.51.100.2", "192.0.2.2", 443, "SUCCESS"), flow(30, "198.51.100.2", "192.0.2.2", 443, "SUCCESS"), flow(60, "198.51.100.2", "192.0.2.2", 443, "SUCCESS"), flow(61, "198.51.100.2", "192.0.2.2", 443, "SUCCESS"));
        List<Alert> a=new ConnectionBurstRule().detect(rs, new RuleSettings(true, 3, 60, "MEDIUM"), Set.of());
        assertEquals(1, a.size());
        assertEquals(3, a.get(0).observedMetric);
    }

    @Test void countsOnlyFailedConnectionsForRepeatedFailureRule() {
        List<FlowRecord> rs=new ArrayList<>();
        for(int i=0; i<8; i++)rs.add(flow(i*2, "203.0.113.4", "192.0.2.9", 22, "FAILED"));
        rs.add(flow(10, "203.0.113.4", "192.0.2.9", 22, "SUCCESS"));
        List<Alert> a=new FailedConnectionsRule().detect(rs, new RuleSettings(true, 8, 120, "HIGH"), Set.of());
        assertEquals(1, a.size());
        assertEquals(8, a.get(0).observedMetric);
    }

    @Test void detectsTrafficSpikeAgainstOtherObservedBuckets() {
        List<FlowRecord> rs=new ArrayList<>();
        for(int i=0; i<3; i++)rs.add(flow(i, "10.0.0.1", "192.0.2.1", 443, "SUCCESS"));
        for(int i=0; i<25; i++)rs.add(flow(120+i, "10.0.0.2", "192.0.2.1", 443, "SUCCESS"));
        for(int i=0; i<3; i++)rs.add(flow(240+i, "10.0.0.3", "192.0.2.1", 443, "SUCCESS"));
        RuleSettings s=new RuleSettings(true, 20, 60, "MEDIUM");
        s.bucketSeconds=60;
        s.baselineMultiplier=2.0;
        List<Alert> a=new TrafficSpikeRule().detect(rs, s, Set.of());
        assertEquals(1, a.size());
        assertEquals(25, a.get(0).observedMetric);
    }

    @Test void deduplicatesSameRuleSameSourceTargetBucket() {
        Alert one=new Alert("rule", "HIGH", "10.0.0.1", "192.0.2.1", "2026-10-27T10:00:10Z", "2026-10-27T10:00:00Z", "2026-10-27T10:00:10Z", 10, 8, "count", "x", List.of());
        Alert two=new Alert("rule", "HIGH", "10.0.0.1", "192.0.2.1", "2026-10-27T10:00:20Z", "2026-10-27T10:00:00Z", "2026-10-27T10:00:20Z", 12, 8, "count", "y", List.of());
        List<Alert> result=new AlertDeduplicator().deduplicate(List.of(one, two), 60);
        assertEquals(1, result.size());
        assertEquals(12, result.get(0).observedMetric);
    }

    @Test void hostSweepDetectsManyDistinctDestinationHostsWithinWindow() {
        List<FlowRecord> rs = new ArrayList<>();
        for (int i = 1; i <= 12; i++) rs.add(flow(i, "198.51.100.77", "192.0.2." + i, 443, "SUCCESS"));
        RuleSettings settings = new RuleSettings(true, 12, 60, "MEDIUM");
        List<Alert> alerts = new HostSweepRule().detect(rs, settings, Set.of());
        assertEquals(1, alerts.size());
        assertEquals("Host Sweep Detection", alerts.get(0).ruleName);
        assertEquals(12, alerts.get(0).observedMetric);
        assertTrue(alerts.get(0).explanation.contains("12 distinct destination hosts"));
    }

    @Test void hostSweepIgnoresDuplicateDestinationAndAllowlistedSources() {
        List<FlowRecord> repeated = List.of(flow(0, "198.51.100.77", "192.0.2.1", 443, "SUCCESS"), flow(1, "198.51.100.77", "192.0.2.1", 80, "SUCCESS"));
        assertTrue(new HostSweepRule().detect(repeated, new RuleSettings(true, 2, 60, "MEDIUM"), Set.of()).isEmpty());
        List<FlowRecord> allowlisted = new ArrayList<>();
        for (int i=1; i<=3; i++) allowlisted.add(flow(i, "127.0.0.1", "192.0.2."+i, 443, "SUCCESS"));
        assertTrue(new HostSweepRule().detect(allowlisted, new RuleSettings(true, 3, 60, "MEDIUM"), Set.of("127.0.0.1")).isEmpty());
    }

    @Test void emptyDatasetProducesNoAlerts() {
        ParseResult parsed=new ParseResult();
        parsed.totalRows=0;
        assertTrue(new com.netsentry.detection.DetectionEngine().analyze(parsed, "empty", new com.netsentry.config.RulesConfig()).alerts.isEmpty());
    }
}
