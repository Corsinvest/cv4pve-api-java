/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

package it.corsinvest.proxmoxve.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Reading the status of a task and waiting for its end.
 */
class TaskTest {

    private static final String UPID = "UPID:cc01:0001A2B3:0C4D5E6F:66FD0000:qmsnapshot:9999:root@pam:";
    private static final String RUNNING = "{\"status\":\"running\",\"node\":\"cc01\"}";
    private static final String STOPPED_OK = "{\"status\":\"stopped\",\"exitstatus\":\"OK\",\"node\":\"cc01\"}";

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
    void nodeIsReadFromTheTaskIdentifier() {
        assertEquals("cc01", PveClientBase.getNodeFromTask(UPID));
    }

    @Test
    void statusIsReadFromTheNodeOfTheTask() {
        server.enqueueData(RUNNING);

        assertTrue(client.taskIsRunning(UPID));

        var request = server.lastRequest();
        assertEquals("GET", request.method());
        assertEquals("/api2/json/nodes/cc01/tasks/" + UPID + "/status", request.path());
    }

    @Test
    void stoppedTaskIsNotRunning() {
        server.enqueueData(STOPPED_OK);

        assertFalse(client.taskIsRunning(UPID));
    }

    @Test
    void exitStatusIsNullWhileTheTaskRuns() {
        server.enqueueData(RUNNING);

        assertNull(client.getExitStatusTask(UPID));
    }

    @Test
    void exitStatusOfAFinishedTask() {
        server.enqueueData("{\"status\":\"stopped\",\"exitstatus\":\"command 'qm' failed: exit code 255\"}");

        assertEquals("command 'qm' failed: exit code 255", client.getExitStatusTask(UPID));
    }

    @Test
    void waitReturnsTrueWhenTheTaskFinishes() {
        server.enqueueData(RUNNING).enqueueData(RUNNING).enqueueData(STOPPED_OK);

        assertTrue(client.waitForTaskToFinish(UPID, 10, 5000));

        assertEquals(3, server.requests().size());
    }

    @Test
    void waitReturnsFalseWhenTheTaskStillRunsAtTheTimeout() {
        server.setDefault(200, "{\"data\":" + RUNNING + "}");

        assertFalse(client.waitForTaskToFinish(UPID, 20, 100));
    }

    @Test
    void statusThatCannotBeReadThrowsWithTheHttpStatus() {
        server.enqueue(500, "{\"data\":null,\"errors\":{\"upid\":\"no such task\"}}");

        var ex = assertThrows(PveResultException.class, () -> client.taskIsRunning(UPID));

        assertEquals(500, ex.getResult().getStatusCode());
        assertTrue(ex.getMessage().contains(UPID));
        assertTrue(ex.getMessage().contains("500"));
        assertTrue(ex.getMessage().contains("upid : no such task"));
    }

    @Test
    void statusWithoutBodyThrows() {
        server.enqueue(403, "");

        var ex = assertThrows(PveResultException.class, () -> client.getExitStatusTask(UPID));

        assertEquals(403, ex.getResult().getStatusCode());
    }

    @Test
    void statusWithoutDataThrows() {
        server.enqueue(200, "{\"data\":null}");

        var ex = assertThrows(PveResultException.class, () -> client.taskIsRunning(UPID));

        assertTrue(ex.getMessage().contains("response does not contain 'data'"));
    }

    @Test
    void waitStopsWhenTheStatusCannotBeRead() {
        server.enqueueData(RUNNING).enqueue(500, "");

        assertThrows(PveResultException.class, () -> client.waitForTaskToFinish(UPID, 10, 5000));

        assertEquals(2, server.requests().size());
    }
}
