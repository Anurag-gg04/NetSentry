package com.netsentry.config;

import com.netsentry.util.Json;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public final class ConfigLoader {

    private ConfigLoader() {
    }

    public static RulesConfig loadDefault() throws IOException {
        Path local = Path.of("config", "rules.json");
        RulesConfig config;
        if (Files.isRegularFile(local)) config = Json.mapper().readValue(Files.readAllBytes(local), RulesConfig.class);
        else try (InputStream in = ConfigLoader.class.getResourceAsStream("/config/rules.json")) {
            config = in == null ? new RulesConfig() : Json.mapper().readValue(in, RulesConfig.class);
        }
        config.validate();
        return config;
    }
}
