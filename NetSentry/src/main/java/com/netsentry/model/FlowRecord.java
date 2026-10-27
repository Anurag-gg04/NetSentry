package com.netsentry.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.time.Instant;

public class FlowRecord {
    public String timestamp;
    public String srcIp;
    public String dstIp;
    public Integer srcPort;
    public Integer dstPort;
    public String protocol;
    public Long packets;
    public Long bytes;
    public String connectionStatus;
    @JsonIgnore public Instant eventTime;

    public FlowRecord() {
    }

    public String getSourceKey() {
        return srcIp + "->" + dstIp;
    }
}
