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
 * Login with ticket, with and without a second factor.
 */
class LoginTest {

    private static final String TICKET = "{\"ticket\":\"PVE:root@pam:TICKET\",\"CSRFPreventionToken\":\"CSRF-TOKEN\"}";
    private static final String NEED_TFA = "{\"ticket\":\"PVE:!tfa!CHALLENGE\",\"NeedTFA\":1}";

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
    void loginAsksTheTicketAndUsesItInTheNextRequests() throws Exception {
        server.enqueueData(TICKET);

        assertTrue(client.login("root", "secret"));
        client.get("/version", null);

        var login = server.requests().get(0);
        assertEquals("POST", login.method());
        assertEquals("/api2/json/access/ticket", login.path());
        assertEquals(3, login.json().size());
        assertEquals("root", login.json().get("username").asText());
        assertEquals("pam", login.json().get("realm").asText());
        assertEquals("secret", login.json().get("password").asText());
        assertNull(login.header("Cookie"));

        var next = server.lastRequest();
        assertEquals("PVEAuthCookie=PVE:root@pam:TICKET", next.header("Cookie"));
        assertEquals("CSRF-TOKEN", next.header("CSRFPreventionToken"));
    }

    @Test
    void realmIsTakenFromTheUsername() throws Exception {
        server.enqueueData(TICKET);

        client.login("admin@pve", "secret");

        var login = server.lastRequest();
        assertEquals("admin", login.json().get("username").asText());
        assertEquals("pve", login.json().get("realm").asText());
    }

    @Test
    void realmCanBeGiven() throws Exception {
        server.enqueueData(TICKET);

        client.login("admin", "secret", "ldap");

        assertEquals("ldap", server.lastRequest().json().get("realm").asText());
    }

    @Test
    void wrongPasswordReturnsFalse() throws Exception {
        server.enqueue(401, "");

        assertFalse(client.login("root", "wrong"));
        client.get("/version", null);

        assertNull(server.lastRequest().header("Cookie"));
        assertNull(server.lastRequest().header("CSRFPreventionToken"));
    }

    @Test
    void secondFactorRequestedWithoutCodeThrows() {
        server.enqueueData(NEED_TFA);

        var ex = assertThrows(PveExceptionAuthentication.class, () -> client.login("root", "secret"));

        assertTrue(ex.getMessage().contains("Two Factor Authentication"));
        assertEquals(200, ex.getResult().getStatusCode());
        assertEquals(1, server.requests().size());
    }

    @Test
    void secondFactorIsSentInASecondCallWithTheChallenge() throws Exception {
        server.enqueueData(NEED_TFA).enqueueData(TICKET);

        assertTrue(client.login("root", "secret", "pam", "123456"));
        client.get("/version", null);

        var requests = server.requests();
        assertEquals(3, requests.size());

        var first = requests.get(0).json();
        assertEquals("secret", first.get("password").asText());
        assertFalse(first.has("tfa-challenge"));

        var second = requests.get(1);
        assertEquals("/api2/json/access/ticket", second.path());
        assertEquals("totp:123456", second.json().get("password").asText());
        assertEquals("PVE:!tfa!CHALLENGE", second.json().get("tfa-challenge").asText());
        assertEquals("root", second.json().get("username").asText());
        assertEquals("pam", second.json().get("realm").asText());

        assertEquals("PVEAuthCookie=PVE:root@pam:TICKET", requests.get(2).header("Cookie"));
    }

    @Test
    void secondFactorRejectedReturnsFalse() throws Exception {
        server.enqueueData(NEED_TFA).enqueue(401, "");

        assertFalse(client.login("root", "secret", "pam", "000000"));
        client.get("/version", null);

        assertNull(server.lastRequest().header("Cookie"));
    }

    @Test
    void secondFactorWithoutTypeIsTotp() {
        assertEquals("totp:123456", PveClientBase.getTfaResponse("123456"));
        assertEquals("recovery:abcd-1234", PveClientBase.getTfaResponse("recovery:abcd-1234"));
    }
}
