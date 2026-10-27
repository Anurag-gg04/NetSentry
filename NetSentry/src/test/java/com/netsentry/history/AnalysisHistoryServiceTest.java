package com.netsentry.history;

import com.netsentry.model.AnalysisResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class AnalysisHistoryServiceTest {
    @TempDir Path temp;

    @Test void savesListsGetsExportsAndDeletesHistory() throws Exception {
        AnalysisHistoryService service = new AnalysisHistoryService(temp.resolve("history"));
        AnalysisResult result = new AnalysisResult();
        result.datasetName = "sample.csv";
        result.analysisTimestamp = "2026-10-28T10:00:00Z";
        result.totalRecords = 10;
        result.acceptedRecords = 9;
        result.rejectedRecords = 1;
        result.alertCount = 2;
        result.severityCounts.put("HIGH", 1);
        result.severityCounts.put("MEDIUM", 1);
        AnalysisHistoryEntry saved = service.save(result);
        assertEquals(saved.id, service.get(saved.id).id);
        assertEquals(1, service.list().size());
        Path exported = service.export(saved.id, temp.resolve("export.json"));
        assertTrue(java.nio.file.Files.readString(exported).contains("sample.csv"));
        assertTrue(service.delete(saved.id));
        assertNull(service.get(saved.id));
    }

    @Test void rejectsInvalidIds() {
        AnalysisHistoryService service = new AnalysisHistoryService(temp.resolve("history"));
        assertThrows(IllegalArgumentException.class, () -> service.get("../../secret"));
    }
}
