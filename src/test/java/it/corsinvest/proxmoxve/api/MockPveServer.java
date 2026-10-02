/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

package it.corsinvest.proxmoxve.api;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Local HTTP server that plays the part of Proxmox VE: it records the requests
 * of the client and answers with the responses queued by the test. When the
 * queue is empty it answers with the default response.
 */
final class MockPveServer implements AutoCloseable {

    /**
     * Request received from the client.
     */
    record Request(String method, String path, String rawQuery, Headers headers, String body) {

        Map<String, String> query() {
            var ret = new LinkedHashMap<String, String>();
            if (rawQuery != null && !rawQuery.isEmpty()) {
                for (var pair : rawQuery.split("&")) {
                    var pos = pair.indexOf('=');
                    ret.put(URLDecoder.decode(pair.substring(0, pos), StandardCharsets.UTF_8),
                            URLDecoder.decode(pair.substring(pos + 1), StandardCharsets.UTF_8));
                }
            }
            return ret;
        }

        JsonNode json() throws IOException {
            return new ObjectMapper().readTree(body);
        }

        String header(String name) {
            return headers.getFirst(name);
        }
    }

    private record Response(int status, byte[] body) {
    }

    private final HttpServer server;
    private final List<Request> requests = new ArrayList<>();
    private final Deque<Response> responses = new ArrayDeque<>();
    private Response defaultResponse = new Response(200, "{\"data\":null}".getBytes(StandardCharsets.UTF_8));

    MockPveServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    private synchronized void handle(HttpExchange exchange) throws IOException {
        var uri = exchange.getRequestURI();
        requests.add(new Request(exchange.getRequestMethod(),
                uri.getPath(),
                uri.getRawQuery(),
                exchange.getRequestHeaders(),
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));

        var response = responses.isEmpty() ? defaultResponse : responses.poll();
        var bytes = response.body();
        exchange.sendResponseHeaders(response.status(), bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    int getPort() {
        return server.getAddress().getPort();
    }

    /**
     * Client connected to this server. The real client always uses https, so the
     * address is replaced.
     */
    PveClient client() {
        return clientAt(getPort());
    }

    /**
     * Client that talks http to a local port, whatever listens there.
     */
    static PveClient clientAt(int port) {
        var address = "http://127.0.0.1:" + port;
        return new PveClient("127.0.0.1", port) {
            @Override
            protected String getBaseAddress() {
                return address;
            }
        };
    }

    /**
     * Queue a response with the status and the body.
     */
    synchronized MockPveServer enqueue(int status, String body) {
        return enqueueBytes(status, body.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Queue a response with the status and a body that is not text.
     */
    synchronized MockPveServer enqueueBytes(int status, byte[] body) {
        responses.add(new Response(status, body));
        return this;
    }

    /**
     * Queue a 200 response with the json as 'data'.
     */
    MockPveServer enqueueData(String json) {
        return enqueue(200, "{\"data\":" + json + "}");
    }

    /**
     * Response used when the queue is empty.
     */
    synchronized MockPveServer setDefault(int status, String body) {
        defaultResponse = new Response(status, body.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    synchronized List<Request> requests() {
        return new ArrayList<>(requests);
    }

    synchronized Request lastRequest() {
        return requests.get(requests.size() - 1);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
