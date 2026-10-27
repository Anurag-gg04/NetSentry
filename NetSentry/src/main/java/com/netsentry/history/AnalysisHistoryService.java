package com.netsentry.history;

import com.netsentry.model.AnalysisResult;
import com.netsentry.util.Json;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

/** Saves analysis summaries as JSON files outside the project directory. */
public final class AnalysisHistoryService {
    private final Path directory;

    public AnalysisHistoryService() {
        String configured = System.getProperty("netsentry.dataDir");
        Path root = configured == null || configured.isBlank() ? Path.of(System.getProperty("user.home"), ".netsentry") : Path.of(configured);
        this.directory = root.resolve("history").toAbsolutePath().normalize();
    }

    public AnalysisHistoryService(Path directory) {
        this.directory = directory.toAbsolutePath().normalize();
    }

    public synchronized AnalysisHistoryEntry save(AnalysisResult result) throws IOException {
        if (result == null || !"completed".equalsIgnoreCase(result.status)) throw new IllegalArgumentException("Only completed analyses can be saved");
        Files.createDirectories(directory);
        AnalysisHistoryEntry entry = AnalysisHistoryEntry.from(result);
        Path target = pathFor(entry.id);
        Path temp = Files.createTempFile(directory, "analysis-", ".tmp");
        try {
            Files.writeString(temp, Json.mapper().writeValueAsString(entry));
            try {
                Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temp, target);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
        return entry;
    }

    public synchronized List<AnalysisHistoryEntry> list() throws IOException {
        if (!Files.isDirectory(directory)) return List.of();
        List<AnalysisHistoryEntry> entries = new ArrayList<>();
        try (Stream<Path> files = Files.list(directory)) {
            for (Path file : files.filter(p -> p.getFileName().toString().matches("[0-9a-fA-F-]{36}\\.json")).toList()) {
                try {
                    entries.add(Json.mapper().readValue(Files.readAllBytes(file), AnalysisHistoryEntry.class));
                } catch (Exception ex) {
                    System.err.println("NetSentry: skipping malformed history record " + file.getFileName());
                }
            }
        }
        entries.sort(Comparator.comparing((AnalysisHistoryEntry e) -> e.timestamp == null ? "" : e.timestamp).reversed());
        return entries;
    }

    public synchronized AnalysisHistoryEntry get(String id) throws IOException {
        Path file = pathFor(id);
        if (!Files.isRegularFile(file)) return null;
        try {
            return Json.mapper().readValue(Files.readAllBytes(file), AnalysisHistoryEntry.class);
        } catch (Exception ex) {
            throw new IOException("History record is malformed: " + id, ex);
        }
    }

    public synchronized boolean delete(String id) throws IOException {
        return Files.deleteIfExists(pathFor(id));
    }

    public synchronized Path export(String id, Path output) throws IOException {
        AnalysisHistoryEntry entry = get(id);
        if (entry == null) throw new IOException("No history record found for ID: " + id);
        Path target = output.toAbsolutePath().normalize();
        if (target.getParent() != null) Files.createDirectories(target.getParent());
        Files.writeString(target, Json.mapper().writeValueAsString(entry));
        return target;
    }

    private Path pathFor(String id) {
        try {
            UUID.fromString(id);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid analysis ID");
        }
        Path path = directory.resolve(id + ".json").normalize();
        if (!path.getParent().equals(directory)) throw new IllegalArgumentException("Invalid analysis ID");
        return path;
    }
}
