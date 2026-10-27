package com.netsentry.ingestion;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class FlowParserTest {
    private final FlowParser parser = new FlowParser();

    @Test void parsesValidCsvAndNormalizesTimestamp() throws Exception {
        String csv = "timestamp,srcIp,dstIp,srcPort,dstPort,protocol,packets,bytes,connectionStatus\n" + "2026-10-27T10:00:00Z,10.0.0.1,192.0.2.1,1234,443,TCP,2,120,SUCCESS\n";
        ParseResult result = parser.parse(csv.getBytes(StandardCharsets.UTF_8), "flows.csv");
        assertEquals(1, result.records.size());
        assertEquals(1, result.totalRows);
        assertEquals(0, result.rejectedRows);
        assertEquals(Integer.valueOf(443), result.records.get(0).dstPort);
        assertNotNull(result.records.get(0).eventTime);
    }

    @Test void rejectsMalformedRowsButKeepsValidRows() throws Exception {
        String csv = "timestamp,srcIp,dstIp,srcPort,dstPort,protocol,packets,bytes,connectionStatus\n" + "2026-10-27T10:00:00Z,10.0.0.1,192.0.2.1,1234,443,TCP,2,120,SUCCESS\n" + "bad-date,999.0.0.1,192.0.2.1,abc,70000,FTP,-2,-4,FAILED\n";
        ParseResult result = parser.parse(csv.getBytes(StandardCharsets.UTF_8), "flows.csv");
        assertEquals(2, result.totalRows);
        assertEquals(1, result.records.size());
        assertEquals(1, result.rejectedRows);
        assertFalse(result.errors.isEmpty());
    }

    @Test void parsesJsonRecords() throws Exception {
        String json = "[{\"timestamp\":\"2026-10-27T10:00:00Z\",\"srcIp\":\"10.0.0.1\",\"dstIp\":\"192.0.2.1\",\"dstPort\":443,\"protocol\":\"TCP\",\"connectionStatus\":\"SUCCESS\"}]";
        ParseResult result = parser.parse(json.getBytes(StandardCharsets.UTF_8), "flows.json");
        assertEquals(1, result.records.size());
        assertEquals(Long.valueOf(0L), result.records.get(0).bytes);
    }

    @Test void unsupportedExtensionIsRejected() {
        assertThrows(java.io.IOException.class, () -> parser.parse("x".getBytes(StandardCharsets.UTF_8), "flows.txt"));
    }

    @Test void oversizedUploadIsRejected() {
        assertThrows(java.io.IOException.class, () -> parser.parse(new byte[(int)FlowParser.MAX_FILE_BYTES + 1], "big.csv"));
    }
}
