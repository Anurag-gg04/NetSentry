package com.netsentry.api;

import com.netsentry.config.RulesConfig;
import org.junit.jupiter.api.Test;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import static org.junit.jupiter.api.Assertions.*;

class ApiServerTest {

    @Test void healthEndpointReturnsJsonAndUnknownRouteReturns404() throws Exception {
        int port;
        try(ServerSocket s=new ServerSocket(0)){
            port=s.getLocalPort();
        }
        ApiServer api=new ApiServer(port, new RulesConfig());
        api.start();
        try {
            HttpClient client=HttpClient.newHttpClient();
            HttpResponse<String> health=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+api.actualPort()+"/api/health")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, health.statusCode());
            assertTrue(health.body().contains("UP"));
            HttpResponse<String> missing=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+api.actualPort()+"/api/nope")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(404, missing.statusCode());
        } finally {
            api.stop();
        }
    }
}
