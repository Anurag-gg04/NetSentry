package com.netsentry.incidents;

import com.netsentry.model.Alert;
import com.netsentry.util.Json;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/** Stores incident cases as local JSON files. */
public class IncidentService {
    private final Path directory;
    private final Object lock = new Object();

    public IncidentService() {
        String configured = System.getProperty("netsentry.dataDir");
        Path root = configured == null || configured.isBlank() ? Path.of(System.getProperty("user.home"), ".netsentry") : Path.of(configured);
        this.directory = root.resolve("incidents");
    }

    public IncidentService(Path directory) {
        this.directory = directory;
    }

    public Incident create(Alert alert, String title) throws IOException {
        if (alert == null || alert.id == null || alert.id.isBlank()) throw new IllegalArgumentException("A valid alert is required.");
        synchronized (lock) {
            Incident incident = Incident.fromAlert(alert, title);
            write(incident);
            return incident;
        }
    }

    public List<Incident> list() throws IOException {
        synchronized (lock) {
            Files.createDirectories(directory);
            List<Incident> incidents = new ArrayList<>();
            try (var paths = Files.list(directory)) {
                for (Path path : paths.filter(p -> p.getFileName().toString().endsWith(".json")).toList()) {
                    try {
                        incidents.add(Json.mapper().readValue(path.toFile(), Incident.class));
                    } catch (Exception ex) {
                        System.err.println("Skipping invalid incident file " + path.getFileName());
                    }
                }
            }
            incidents.sort(Comparator.comparing((Incident i) -> i.updatedAt == null ? "" : i.updatedAt).reversed());
            return incidents;
        }
    }

    public Incident get(String id) throws IOException {
        synchronized (lock) {
            Path path = path(id);
            return Files.isRegularFile(path) ? Json.mapper().readValue(path.toFile(), Incident.class) : null;
        }
    }

    public Incident update(String id, String status, String assignedTo, String notes) throws IOException {
        synchronized (lock) {
            Incident incident = get(id);
            if (incident == null) return null;
            if (status != null) {
                String normalized = status.trim().toUpperCase(Locale.ROOT);
                if (!List.of("OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE").contains(normalized)) throw new IllegalArgumentException("status must be OPEN, INVESTIGATING, RESOLVED, or FALSE_POSITIVE.");
                incident.status = normalized;
            }
            if (assignedTo != null) incident.assignedTo = assignedTo.trim().isEmpty() ? "Unassigned" : assignedTo.trim();
            if (notes != null) incident.notes = notes.trim();
            incident.updatedAt = Instant.now().toString();
            write(incident);
            return incident;
        }
    }

    public boolean delete(String id) throws IOException {
        synchronized (lock) {
            return Files.deleteIfExists(path(id));
        }
    }

    private Path path(String id) {
        try {
            UUID.fromString(id);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Provide a valid incident ID.");
        }
        return directory.resolve(id + ".json");
    }

    private void write(Incident incident) throws IOException {
        Files.createDirectories(directory);
        Path target = path(incident.id);
        Path temp = Files.createTempFile(directory, "incident-", ".tmp");
        try {
            Json.mapper().writeValue(temp.toFile(), incident);
            try {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }
}
