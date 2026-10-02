/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

package it.corsinvest.proxmoxve.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * How a request is sent and how the response becomes a Result.
 */
class RequestTest {

    private MockPveServer server;
    private PveClient client;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockPveServer();
        client = server.client();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    private static Map<String, Object> parameters() {
        var parameters = new HashMap<String, Object>();
        parameters.put("name", "città & co=1");
        parameters.put("vmid", 100);
        parameters.put("full", true);
        parameters.put("force", false);
        parameters.put("missing", null);
        return parameters;
    }

    @Test
    void apiUrlIsHttpsWithHostAndPort() {
        assertEquals("https://pve.local:8006/api2/json", new PveClient("pve.local", 8006).getApiUrl());
    }

    @Test
    void getSendsParametersInQueryString() {
        client.get("/nodes", parameters());

        var request = server.lastRequest();
        assertEquals("GET", request.method());
        assertEquals("/api2/json/nodes", request.path());
        assertEquals(Map.of("name", "città & co=1", "vmid", "100", "full", "1", "force", "0"), request.query());
        assertEquals("", request.body());
    }

    @Test
    void getWithoutParametersHasNoQueryString() {
        client.get("/version", null);

        assertNull(server.lastRequest().rawQuery());
    }

    @Test
    void createSendsParametersAsJsonBody() throws IOException {
        client.create("/nodes/cc01/qemu", parameters());

        var request = server.lastRequest();
        assertEquals("POST", request.method());
        assertEquals("/api2/json/nodes/cc01/qemu", request.path());
        assertNull(request.rawQuery());
        assertEquals("application/json; charset=UTF-8", request.header("Content-Type"));

        var json = request.json();
        assertEquals(4, json.size());
        assertEquals("città & co=1", json.get("name").asText());
        assertEquals(100, json.get("vmid").asInt());
        assertEquals(1, json.get("full").asInt());
        assertEquals(0, json.get("force").asInt());
    }

    @Test
    void setSendsPut() throws IOException {
        client.set("/nodes/cc01/qemu/100/config", Map.of("memory", 2048));

        var request = server.lastRequest();
        assertEquals("PUT", request.method());
        assertEquals(2048, request.json().get("memory").asInt());
    }

    @Test
    void deleteSendsParametersInQueryString() {
        client.delete("/nodes/cc01/qemu/100/snapshot/snap1", parameters());

        var request = server.lastRequest();
        assertEquals("DELETE", request.method());
        assertEquals("/api2/json/nodes/cc01/qemu/100/snapshot/snap1", request.path());
        assertEquals(Map.of("name", "città & co=1", "vmid", "100", "full", "1", "force", "0"), request.query());
    }

    @Test
    void apiTokenIsSentInAuthorizationHeader() {
        client.setApiToken("root@pam!test=11111111-2222-3333-4444-555555555555");
        client.get("/version", null);

        var request = server.lastRequest();
        assertEquals("PVEAPIToken root@pam!test=11111111-2222-3333-4444-555555555555",
                request.header("Authorization"));
        assertNull(request.header("Cookie"));
        assertNull(request.header("CSRFPreventionToken"));
    }

    @Test
    void successResponseBecomesResult() {
        server.enqueueData("{\"version\":\"9.2.1\",\"release\":\"9.2\"}");
        var parameters = Map.<String, Object>of("verbose", true);

        var result = client.get("/version", parameters);

        assertTrue(result.isSuccessStatusCode());
        assertEquals(200, result.getStatusCode());
        assertFalse(result.responseInError());
        assertEquals("9.2.1", result.getData().get("version").asText());
        assertEquals("/version", result.getRequestResource());
        assertEquals(MethodType.GET, result.getMethodType());
        assertEquals(ResponseType.JSON, result.getResponseType());
        assertSame(parameters, result.getRequestParameters());
        assertSame(result, client.getLastResult());
    }

    @Test
    void errorResponseKeepsStatusAndErrors() {
        server.enqueue(500, "{\"data\":null,\"errors\":{\"vmid\":\"invalid format\",\"name\":\"too long\"}}");

        var result = client.create("/nodes/cc01/qemu", Map.of("vmid", "x"));

        assertFalse(result.isSuccessStatusCode());
        assertEquals(500, result.getStatusCode());
        assertTrue(result.responseInError());
        assertEquals("vmid : invalid format\nname : too long", result.getError());
    }

    @Test
    void errorResponseWithoutBodyHasNoData() {
        server.enqueue(501, "");

        var result = client.get("/cluster/ceph/health-mute", null);

        assertFalse(result.isSuccessStatusCode());
        assertEquals(501, result.getStatusCode());
        assertNull(result.getResponse());
        assertNull(result.getData());
    }

    @Test
    void responseThatIsNotJsonIsNotSuccess() {
        server.enqueue(502, "<html>Bad Gateway</html>");

        var result = client.get("/version", null);

        assertFalse(result.isSuccessStatusCode());
        assertEquals(502, result.getStatusCode());
        assertNull(result.getResponse());
    }

    @Test
    void serverNotReachableGivesFailedResult() throws IOException {
        int freePort;
        try (var socket = new ServerSocket(0)) {
            freePort = socket.getLocalPort();
        }
        var unreachable = new PveClient("127.0.0.1", freePort);
        unreachable.setTimeout(2000);

        var result = unreachable.get("/version", null);

        assertFalse(result.isSuccessStatusCode());
        assertEquals(0, result.getStatusCode());
        assertNull(result.getData());
    }

    @Test
    void pngResponseIsReturnedAsDataUrl() {
        server.enqueue(200, "png-bytes");
        client.setResponseType(ResponseType.PNG);

        var result = client.get("/nodes/cc01/rrd", null);

        assertEquals(ResponseType.PNG, result.getResponseType());
        assertTrue(result.getData().asText().startsWith("data:image/png;base64,cG5nLWJ5dGVz"));
    }

    @Test
    void negativeTimeoutIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> client.setTimeout(-1));
        client.setTimeout(1500);
        assertEquals(1500, client.getTimeout());
    }

    @Test
    void indexedParametersAreAddedWithTheIndexAsSuffix() {
        var parameters = new HashMap<String, Object>();

        PveClientBase.addIndexedParameter(parameters, "net", Map.of(0, "virtio,bridge=vmbr0", 3, "e1000"));
        PveClientBase.addIndexedParameter(parameters, "scsi", null);

        assertEquals(Map.of("net0", "virtio,bridge=vmbr0", "net3", "e1000"), parameters);
    }
}
