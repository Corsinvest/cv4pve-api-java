/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

package it.corsinvest.proxmoxve.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The generated classes: path, method and parameter names of the request.
 */
class GeneratedClientTest {

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

    @Test
    void version() {
        client.getVersion().version();

        assertEquals("GET", server.lastRequest().method());
        assertEquals("/api2/json/version", server.lastRequest().path());
    }

    @Test
    void optionalParameterGoesInTheQueryString() {
        client.getCluster().getResources().resources("vm");

        assertEquals("/api2/json/cluster/resources", server.lastRequest().path());
        assertEquals(Map.of("type", "vm"), server.lastRequest().query());
    }

    @Test
    void indexersBuildThePath() {
        client.getNodes().get("cc01").getQemu().get(9999).getStatus().getCurrent().vmStatus();

        assertEquals("GET", server.lastRequest().method());
        assertEquals("/api2/json/nodes/cc01/qemu/9999/status/current", server.lastRequest().path());
    }

    @Test
    void createSnapshot() throws IOException {
        client.getNodes().get("cc01").getQemu().get(9999).getSnapshot().snapshot("snap1", "before update", false);

        var request = server.lastRequest();
        assertEquals("POST", request.method());
        assertEquals("/api2/json/nodes/cc01/qemu/9999/snapshot", request.path());
        assertEquals(3, request.json().size());
        assertEquals("snap1", request.json().get("snapname").asText());
        assertEquals("before update", request.json().get("description").asText());
        assertEquals(0, request.json().get("vmstate").asInt());
    }

    @Test
    void deleteSnapshotSendsForceInTheQueryString() {
        client.getNodes().get("cc01").getQemu().get(9999).getSnapshot().get("snap1").delsnapshot(true);

        var request = server.lastRequest();
        assertEquals("DELETE", request.method());
        assertEquals("/api2/json/nodes/cc01/qemu/9999/snapshot/snap1", request.path());
        assertEquals(Map.of("force", "1"), request.query());
    }

    @Test
    void deleteSnapshotWithoutParameters() {
        client.getNodes().get("cc01").getLxc().get(105).getSnapshot().get("snap1").delsnapshot();

        var request = server.lastRequest();
        assertEquals("DELETE", request.method());
        assertEquals("/api2/json/nodes/cc01/lxc/105/snapshot/snap1", request.path());
        assertNull(request.rawQuery());
    }

    @Test
    void parameterNameWithDashIsSentWithTheDash() throws IOException {
        client.getCluster().getCeph().getRestartBulk().restartBulk("osd", true, null, true, 60);

        var request = server.lastRequest();
        assertEquals("POST", request.method());
        assertEquals("/api2/json/cluster/ceph/restart-bulk", request.path());
        assertEquals(4, request.json().size());
        assertEquals("osd", request.json().get("service-type").asText());
        assertEquals(1, request.json().get("dry-run").asInt());
        assertEquals(1, request.json().get("only-outdated").asInt());
        assertEquals(60, request.json().get("timeout").asInt());
    }

    @Test
    void haRuleParametersAreSentByName() throws IOException {
        client.getCluster().getHa().getRules().createRule("rule1", "node-affinity", "vm:100,vm:101");

        var request = server.lastRequest();
        assertEquals("POST", request.method());
        assertEquals("/api2/json/cluster/ha/rules", request.path());
        assertEquals("rule1", request.json().get("rule").asText());
        assertEquals("node-affinity", request.json().get("type").asText());
        assertEquals("vm:100,vm:101", request.json().get("resources").asText());
    }

    @Test
    void cephHealthMute() throws IOException {
        client.getCluster().getCeph().getHealthMute().get("OSD_DOWN").healthMute(true, null, "2h");

        var request = server.lastRequest();
        assertEquals("PUT", request.method());
        assertEquals("/api2/json/cluster/ceph/health-mute/OSD_DOWN", request.path());
        assertEquals(2, request.json().size());
        assertEquals(1, request.json().get("value").asInt());
        assertEquals("2h", request.json().get("ttl").asText());
    }

    @Test
    void routeMapEntryTakesThePathValuesFromTheIndexers() {
        client.getCluster().getSdn().getRouteMaps().getEntries().get("map1").getEntry().get(10)
                .deleteRouteMapEntry("lock-123");

        var request = server.lastRequest();
        assertEquals("DELETE", request.method());
        assertEquals("/api2/json/cluster/sdn/route-maps/entries/map1/entry/10", request.path());
        assertEquals(Map.of("lock-token", "lock-123"), request.query());
    }
}
