/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

package it.corsinvest.proxmoxve.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * What the caller gets when a request fails: no answer, an answer that is not
 * the one of Proxmox VE, a task that does not exist. And what the log shows.
 */
class FailureTest {

    private static final String UPID = "UPID:cc01:0001A2B3:0C4D5E6F:66FD0000:qmsnapshot:9999:root@pam:";
    private static final String TICKET = "{\"ticket\":\"PVE:root@pam:SECRETTICKET\",\"CSRFPreventionToken\":\"SECRETCSRF\",\"username\":\"root@pam\"}";

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
    void successStatusWithABodyThatIsNotJsonIsAnError() {
        server.enqueue(200, "<html>proxy login</html>");

        var result = client.get("/version", null);

        assertFalse(result.isSuccessStatusCode());
        assertEquals(502, result.getStatusCode());
        assertEquals("The answer is not JSON (HTTP 200): <html>proxy login</html>", result.getReasonPhrase());
    }

    @Test
    void errorHelpersWorkWithoutAResponse() throws IOException {
        int freePort;
        try (var socket = new ServerSocket(0)) {
            freePort = socket.getLocalPort();
        }
        var unreachable = MockPveServer.clientAt(freePort);
        unreachable.setTimeout(2000);

        var result = unreachable.get("/version", null);

        assertEquals(0, result.getStatusCode());
        assertFalse(result.responseInError());
        assertEquals("", result.getError());
        assertFalse(result.getReasonPhrase().isEmpty(), "the reason of the failure is reported");
    }

    @Test
    void nodeThatAcceptsTheConnectionAndDoesNotAnswerTimesOut() throws IOException {
        // accepts the connection (backlog of the system) and never answers
        try (var silent = new ServerSocket(0)) {
            var hanging = MockPveServer.clientAt(silent.getLocalPort());
            hanging.setTimeout(300);

            var result = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> hanging.get("/version", null));

            assertFalse(result.isSuccessStatusCode());
            assertEquals(408, result.getStatusCode());
            assertFalse(result.getReasonPhrase().isEmpty());
        }
    }

    @Test
    void pngBytesAreReturnedAsTheyAre() {
        var png = new byte[] { (byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', (byte) 0xff, 0x00, (byte) 0xfe };
        server.enqueueBytes(200, png);
        client.setResponseType(ResponseType.PNG);

        var result = client.get("/nodes/cc01/rrd", null);

        assertEquals("data:image/png;base64," + Base64.getEncoder().encodeToString(png), result.getData().asText());
        assertTrue(server.lastRequest().path().startsWith("/api2/png/"), server.lastRequest().path());
    }

    @Test
    void pngErrorAnswerKeepsStatusAndErrors() {
        server.enqueue(400, "{\"data\":null,\"errors\":{\"ds\":\"invalid\"}}");
        client.setResponseType(ResponseType.PNG);

        var result = client.get("/nodes/cc01/rrd", null);

        assertEquals(400, result.getStatusCode());
        assertTrue(result.responseInError());
        assertEquals("ds : invalid", result.getError());
    }

    @Test
    void loginAndTaskStatusAreReadAsJsonAlsoInPngMode() throws Exception {
        client.setResponseType(ResponseType.PNG);

        server.enqueueData(TICKET);
        assertTrue(client.login("root@pam", "secret"));
        assertEquals("/api2/json/access/ticket", server.lastRequest().path());

        server.enqueueData("{\"status\":\"stopped\",\"exitstatus\":\"OK\"}");
        assertEquals("OK", client.getExitStatusTask(UPID));
        assertTrue(server.lastRequest().path().startsWith("/api2/json/nodes/cc01/tasks/"));

        assertEquals(ResponseType.PNG, client.getResponseType());
    }

    @Test
    void apiUrlFollowsTheResponseType() {
        var real = new PveClient("pve01", 8006);
        assertEquals("https://pve01:8006/api2/json", real.getApiUrl());

        real.setResponseType(ResponseType.PNG);
        assertEquals("https://pve01:8006/api2/png", real.getApiUrl());
    }

    @Test
    void taskIdentifierThatIsNotAUpidIsRefusedBeforeAnyRequest() {
        for (var task : new String[] { null, "", "abc" }) {
            var ex = assertThrows(PveResultException.class, () -> client.taskIsRunning(task));
            assertTrue(ex.getMessage().contains("not a valid task"), ex.getMessage());
            assertThrows(PveResultException.class, () -> client.getExitStatusTask(task));
            assertThrows(PveResultException.class, () -> client.waitForTaskToFinish(task, 1, 5));
            assertThrows(PveResultException.class, () -> PveClientBase.getNodeFromTask(task));
        }
        assertEquals(0, server.requests().size());
    }

    @Test
    void loginAnsweredWithoutATicketIsNotALogin() throws Exception {
        server.enqueue(200, "<html>proxy login</html>");
        assertFalse(client.login("root@pam", "secret"));

        server.enqueue(200, "");
        assertFalse(client.login("root@pam", "secret"));

        server.enqueueData("{}");
        assertFalse(client.login("root@pam", "secret"));

        server.enqueue(200, "{\"data\":null}");
        assertFalse(client.login("root@pam", "secret"));
    }

    @Test
    void realmIsReadAfterTheLastAt() throws Exception {
        server.enqueueData(TICKET);

        client.login("john@example.com@ldap", "secret");

        var body = server.lastRequest().json();
        assertEquals("john@example.com", body.get("username").asText());
        assertEquals("ldap", body.get("realm").asText());
    }

    @Test
    void logDoesNotShowTheTicketTheCsrfTokenOrSecretsInTheQuery() throws Exception {
        var logger = Logger.getLogger(PveClientBase.class.getName());
        var lines = new ArrayList<String>();
        var formatter = new SimpleFormatter();
        var handler = new Handler() {
            @Override
            public void publish(LogRecord entry) {
                lines.add(formatter.formatMessage(entry));
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        handler.setLevel(Level.ALL);
        var oldLevel = logger.getLevel();
        var oldUseParent = logger.getUseParentHandlers();
        logger.setLevel(Level.ALL);
        logger.setUseParentHandlers(false);
        logger.addHandler(handler);

        try {
            server.enqueueData(TICKET);
            assertTrue(client.login("root@pam", "SECRETPASSWORD"));

            var parameters = new HashMap<String, Object>();
            parameters.put("vncticket", "SECRETQUERY");
            parameters.put("port", 5900);
            client.get("/nodes/cc01/qemu/100/vncwebsocket", parameters);
        } finally {
            logger.removeHandler(handler);
            logger.setLevel(oldLevel);
            logger.setUseParentHandlers(oldUseParent);
        }

        var log = String.join("\n", lines);
        assertFalse(log.isEmpty(), "nothing was logged");
        for (var secret : List.of("SECRETTICKET", "SECRETCSRF", "SECRETPASSWORD", "SECRETQUERY")) {
            assertFalse(log.contains(secret), "the log shows " + secret);
        }
        assertTrue(log.contains("root@pam"), "values that are not secret are still logged");
        assertTrue(log.contains("5900"), "parameters that are not secret are still logged");
    }
}
