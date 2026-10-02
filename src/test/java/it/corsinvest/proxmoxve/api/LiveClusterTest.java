/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

package it.corsinvest.proxmoxve.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Tests on a real Proxmox VE, run with 'mvn test -P live'.
 * Connection from the environment: PVE_HOST, PVE_PORT (default 8006),
 * PVE_API_TOKEN, PVE_TEST_VMID. They only read, except on the QEMU test VM
 * PVE_TEST_VMID, where they change the description and create and delete a
 * snapshot.
 */
@Tag("live")
class LiveClusterTest {

    private static PveClient client;
    private static String testVmId;
    private static String testNode;

    @BeforeAll
    static void connect() {
        var host = System.getenv("PVE_HOST");
        var apiToken = System.getenv("PVE_API_TOKEN");
        testVmId = System.getenv("PVE_TEST_VMID");
        assumeTrue(isSet(host) && isSet(apiToken), "PVE_HOST and PVE_API_TOKEN not set");

        var port = System.getenv("PVE_PORT");
        client = new PveClient(host, isSet(port) ? Integer.parseInt(port) : 8006);
        client.setApiToken(apiToken);
        client.setTimeout(10000);

        if (isSet(testVmId)) {
            for (var vm : ok(client.getCluster().getResources().resources("vm")).getData()) {
                if (vm.path("vmid").asText().equals(testVmId) && vm.path("type").asText().equals("qemu")) {
                    testNode = vm.path("node").asText();
                }
            }
        }
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    private static Result ok(Result result) {
        assertTrue(result.isSuccessStatusCode(),
                () -> result.getStatusCode() + " " + result.getReasonPhrase() + " " + result.getRequestResource());
        assertFalse(result.responseInError(), result::getError);
        return result;
    }

    private static PveClient.PVENodes.PVENodeItem.PVEQemu.PVEVmidItem testVm() {
        assumeTrue(testNode != null, "PVE_TEST_VMID not set or not a QEMU VM of the cluster");
        return client.getNodes().get(testNode).getQemu().get(testVmId);
    }

    private static void runTask(Result result) {
        var upid = ok(result).getData().asText();
        assertTrue(upid.startsWith("UPID:"), upid);
        assertTrue(client.waitForTaskToFinish(upid, 500, 120000), "task still running: " + upid);
        assertEquals("OK", client.getExitStatusTask(upid));
    }

    private static boolean hasSnapshot(JsonNode snapshots, String name) {
        for (var snapshot : snapshots) {
            if (snapshot.path("name").asText().equals(name)) {
                return true;
            }
        }
        return false;
    }

    @Test
    void version() {
        var data = ok(client.getVersion().version()).getData();

        assertTrue(data.get("version").asText().matches("\\d+\\.\\d+.*"), data.toString());
        assertNotNull(data.get("release"));
    }

    @Test
    void nodesAndTheirStatus() {
        var nodes = ok(client.getNodes().index()).getData();
        assertTrue(nodes.size() > 0);

        for (var node : nodes) {
            if (node.path("status").asText().equals("online")) {
                var status = ok(client.getNodes().get(node.get("node").asText()).getStatus().status()).getData();
                assertTrue(status.get("uptime").asLong() > 0);
            }
        }
    }

    @Test
    void clusterResourcesFilteredByType() {
        var resources = ok(client.getCluster().getResources().resources("vm")).getData();

        for (var resource : resources) {
            var type = resource.get("type").asText();
            assertTrue(type.equals("qemu") || type.equals("lxc"), type);
        }
    }

    @Test
    void qemuListOfEveryNode() {
        for (var node : ok(client.getNodes().index()).getData()) {
            if (node.path("status").asText().equals("online")) {
                var vms = ok(client.getNodes().get(node.get("node").asText()).getQemu().vmlist()).getData();
                for (var vm : vms) {
                    assertTrue(vm.get("vmid").asLong() > 0);
                }
            }
        }
    }

    @Test
    void resourceThatDoesNotExistIsAnError() {
        var result = client.getNodes().get("node-that-does-not-exist").getQemu().vmlist();

        assertFalse(result.isSuccessStatusCode());
        assertTrue(result.getStatusCode() >= 400, String.valueOf(result.getStatusCode()));
    }

    @Test
    void wrongApiTokenIsRejected() {
        var other = new PveClient(client.getHostname(), client.getPort());
        other.setApiToken("root@pam!none=00000000-0000-0000-0000-000000000000");

        var result = other.getNodes().index();

        assertEquals(401, result.getStatusCode());
    }

    @Test
    void testVmConfigAndStatus() {
        var vm = testVm();

        var config = ok(vm.getConfig().vmConfig()).getData();
        assertNotNull(config.get("digest"));

        var status = ok(vm.getStatus().getCurrent().vmStatus()).getData();
        assertEquals(testVmId, status.get("vmid").asText());
    }

    @Test
    void testVmDescriptionIsChangedAndRestored() {
        var vm = testVm();
        var resource = "/nodes/" + testNode + "/qemu/" + testVmId + "/config";
        var before = ok(vm.getConfig().vmConfig()).getData().path("description").asText("");
        var value = "cv4pve-api-java live test " + System.currentTimeMillis() + " àèì";

        try {
            ok(client.set(resource, Map.of("description", value)));
            assertEquals(value, ok(vm.getConfig().vmConfig()).getData().get("description").asText().trim());
        } finally {
            ok(before.isEmpty()
                    ? client.set(resource, Map.of("delete", "description"))
                    : client.set(resource, Map.of("description", before)));
        }

        assertEquals(before, ok(vm.getConfig().vmConfig()).getData().path("description").asText(""));
    }

    @Test
    void testVmSnapshotIsCreatedUpdatedAndDeleted() {
        var vm = testVm();
        var name = "livetest" + System.currentTimeMillis() / 1000;

        runTask(vm.getSnapshot().snapshot(name, "created by cv4pve-api-java", false));
        try {
            assertTrue(hasSnapshot(ok(vm.getSnapshot().snapshotList()).getData(), name));

            ok(vm.getSnapshot().get(name).getConfig().updateSnapshotConfig("updated by cv4pve-api-java"));
            var config = ok(vm.getSnapshot().get(name).getConfig().getSnapshotConfig()).getData();
            assertEquals("updated by cv4pve-api-java", config.get("description").asText().trim());
        } finally {
            // DELETE with a parameter in the query string
            runTask(vm.getSnapshot().get(name).delsnapshot(false));
        }

        assertFalse(hasSnapshot(ok(vm.getSnapshot().snapshotList()).getData(), name));
    }

    @Test
    void chartOfANodeIsAPngImage() {
        var node = ok(client.getNodes().index()).getData().get(0).path("node").asText();
        var parameters = new HashMap<String, Object>();
        parameters.put("ds", "cpu");
        parameters.put("timeframe", "hour");

        client.setResponseType(ResponseType.PNG);
        Result result;
        try {
            result = client.get("/nodes/" + node + "/rrd", parameters);
        } finally {
            client.setResponseType(ResponseType.JSON);
        }

        assertTrue(result.isSuccessStatusCode(), () -> result.getStatusCode() + " " + result.getReasonPhrase());
        var prefix = "data:image/png;base64,";
        var uri = result.getData().asText();
        assertTrue(uri.startsWith(prefix));
        var bytes = Base64.getDecoder().decode(uri.substring(prefix.length()));
        // signature of a PNG file
        assertEquals((byte) 0x89, bytes[0]);
        assertEquals("PNG", new String(bytes, 1, 3, java.nio.charset.StandardCharsets.US_ASCII));
    }

    @Test
    void reasonOfAnErrorIsTheMessageOfProxmoxVe() {
        var node = ok(client.getNodes().index()).getData().get(0).path("node").asText();

        var result = client.get("/nodes/" + node + "/qemu/999999/config", null);

        assertFalse(result.isSuccessStatusCode());
        assertTrue(result.getReasonPhrase().contains("does not exist"), result.getReasonPhrase());
        assertFalse(result.responseInError());
    }

    @Test
    void selfSignedCertificateIsRefusedWhenValidated() {
        var strict = new PveClient(client.getHostname(), client.getPort());
        strict.setApiToken(client.getApiToken());
        strict.setTimeout(10000);
        strict.setValidateCertificate(true);

        var result = strict.getVersion().version();

        // a node with a certificate of a trusted authority answers 200: nothing to check there
        assumeTrue(!result.isSuccessStatusCode(), "the node has a trusted certificate");
        assertEquals(0, result.getStatusCode());
        assertFalse(result.getReasonPhrase().isEmpty());
        assertEquals("", result.getError());
    }
}
