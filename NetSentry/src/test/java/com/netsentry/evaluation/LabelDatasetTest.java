package com.netsentry.evaluation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class LabelDatasetTest {
    @TempDir Path temp;

    @Test void readsGroundTruthLabels() throws Exception {
        Path file = temp.resolve("labels.csv");
        Files.writeString(file, "srcIp,label\n198.51.100.1,SUSPICIOUS\n192.0.2.1,NORMAL\n");
        var labels = LabelDataset.read(file);
        assertEquals(2, labels.size());
        assertTrue(labels.get("198.51.100.1"));
        assertFalse(labels.get("192.0.2.1"));
    }

    @Test void rejectsInvalidLabelsAndDuplicateHosts() throws Exception {
        Path invalid = temp.resolve("invalid.csv");
        Files.writeString(invalid, "srcIp,label\n192.0.2.1,MAYBE\n");
        assertThrows(IOException.class, () -> LabelDataset.read(invalid));
        Path duplicate = temp.resolve("duplicate.csv");
        Files.writeString(duplicate, "srcIp,label\n192.0.2.1,NORMAL\n192.0.2.1,SUSPICIOUS\n");
        assertThrows(IOException.class, () -> LabelDataset.read(duplicate));
    }
}
