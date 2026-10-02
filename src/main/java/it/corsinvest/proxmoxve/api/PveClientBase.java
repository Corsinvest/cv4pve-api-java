/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */
package it.corsinvest.proxmoxve.api;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Proxmox VE Client Base
 */
public class PveClientBase {

    private static final Logger logger = Logger.getLogger(PveClientBase.class.getName());
    private static final String[] SENSITIVE_NAMES = { "password", "token", "ticket", "otp", "apitoken", "tfa-challenge" };

    private String _ticketCSRFPreventionToken;
    private String _ticketPVEAuthCookie;
    private final String _hostname;
    private final int _port;
    private Result _lastResult;
    private ResponseType _responseType = ResponseType.JSON;
    private String _apiToken;
    private Proxy _proxy = Proxy.NO_PROXY;
    private int _timeout = 0;
    private boolean _validateCertificate = false;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public PveClientBase(String hostname, int port) {
        _hostname = hostname;
        _port = port;
    }

    /**
     * Gets the hostname configured.
     *
     * @return String The configured hostname.
     */
    public String getHostname() {
        return _hostname;
    }

    /**
     * Gets the port configured.
     *
     * @return int The configured port.
     */
    public int getPort() {
        return _port;
    }

    /**
     * Get Validate Certificate
     *
     * @return boolean Whether SSL certificate validation is enabled
     */
    public boolean getValidateCertificate() {
        return _validateCertificate;
    }

    /**
     * Set Validate Certificate
     *
     * @param validateCertificate Whether to validate SSL certificates
     */
    public void setValidateCertificate(boolean validateCertificate) {
        _validateCertificate = validateCertificate;
    }

    /**
     * Get proxy
     *
     * @return Proxy Current proxy configuration
     */
    public Proxy getProxy() {
        return _proxy;
    }

    /**
     * Set proxy
     *
     * @param proxy Proxy configuration to use
     */
    public void setProxy(Proxy proxy) {
        _proxy = proxy;
    }

    /**
     * Get the response type that is going to be returned when doing requests
     * (json, png).
     *
     * @return ResponseType Current response type configuration
     */
    public ResponseType getResponseType() {
        return _responseType;
    }

    /**
     * Set the response type that is going to be returned when doing requests
     * (json, png).
     *
     * @param responseType Response type to set
     */
    public void setResponseType(ResponseType responseType) {
        _responseType = responseType;
    }

    /**
     * Set the timeout of a request: the longest wait to connect and the longest
     * wait for data once connected. 0, the default, means no limit.
     *
     * @param timeout Timeout in milliseconds
     */
    public void setTimeout(int timeout) {
        if (timeout < 0) {
            throw new IllegalArgumentException("timeout can not be negative");
        }
        _timeout = timeout;
    }

    /**
     * Return the timeout of a request
     *
     * @return int Timeout in milliseconds, 0 for no limit
     */
    public int getTimeout() {
        return _timeout;
    }

    /**
     * Creation ticket from login.
     *
     * @param username user name or &lt;username&gt;@&lt;realm&gt;; without a
     *                 realm it is pam
     * @param password password connection
     * @return boolean true when Proxmox VE gave a ticket; when false the reason
     *         is in {@link #getLastResult()}
     * @throws PveExceptionAuthentication if the user needs a second factor
     */
    public boolean login(String username, String password) throws PveExceptionAuthentication {
        var realm = "pam";

        // user@realm: the realm is what follows the last @
        var at = username.lastIndexOf('@');
        if (at > 0) {
            realm = username.substring(at + 1);
            username = username.substring(0, at);
        }

        return login(username, password, realm, null);
    }

    /**
     * Creation ticket from login.
     *
     * @param username user name
     * @param password password connection
     * @param realm    pam/pve or custom
     * @return boolean true when Proxmox VE gave a ticket; when false the reason
     *         is in {@link #getLastResult()}
     * @throws PveExceptionAuthentication if the user needs a second factor
     */
    public boolean login(String username, String password, String realm)
            throws PveExceptionAuthentication {
        return login(username, password, realm, null);
    }

    /**
     * Creation ticket from login.
     *
     * @param username user name
     * @param password password connection
     * @param realm    pam/pve or custom
     * @param otp      Second factor of a user with two-factor authentication: a
     *                 TOTP code (e.g. 123456) or 'type:value' (e.g.
     *                 recovery:abcd-1234).
     * @return boolean true when Proxmox VE gave a ticket; when false the reason
     *         is in {@link #getLastResult()}
     * @throws PveExceptionAuthentication if the user needs a second factor and
     *                                    otp is missing
     */
    public boolean login(String username, String password, String realm, String otp)
            throws PveExceptionAuthentication {
        var params = new java.util.HashMap<String, Object>();
        params.put("password", password);
        params.put("username", username);
        params.put("realm", realm);
        var result = executeAction("/access/ticket", MethodType.CREATE, params, ResponseType.JSON);

        var data = result.getData();
        if (result.isSuccessStatusCode() && data != null && data.has("NeedTFA")) {
            if (otp == null || otp.isBlank()) {
                throw new PveExceptionAuthentication(result,
                        "Couldn't authenticate user: missing Two Factor Authentication (TFA)");
            }

            // second step: the response to the challenge of the first one
            var tfaParams = new java.util.HashMap<String, Object>();
            tfaParams.put("password", getTfaResponse(otp));
            tfaParams.put("username", username);
            tfaParams.put("realm", realm);
            tfaParams.put("tfa-challenge", data.path("ticket").asText());
            result = executeAction("/access/ticket", MethodType.CREATE, tfaParams, ResponseType.JSON);
            data = result.getData();
        }

        // logged only with a ticket: a success status alone (e.g. the page of a proxy) is not a login
        if (!result.isSuccessStatusCode()
                || data == null
                || !data.hasNonNull("ticket")
                || !data.hasNonNull("CSRFPreventionToken")) {
            return false;
        }

        _ticketCSRFPreventionToken = data.get("CSRFPreventionToken").asText();
        _ticketPVEAuthCookie = data.get("ticket").asText();
        return true;
    }

    /**
     * Second factor as Proxmox VE expects it in the response to a TFA challenge:
     * 'type:value'. A code without a type is a TOTP code.
     *
     * @param otp second factor
     * @return response to the TFA challenge
     */
    static String getTfaResponse(String otp) {
        return otp.contains(":") ? otp : "totp:" + otp;
    }

    /**
     * Returns the base URL used to interact with the Proxmox VE API, for the
     * response type of the client (json, png).
     *
     * @return The proxmox API URL.
     */
    public String getApiUrl() {
        return getApiUrl(getResponseType());
    }

    private String getApiUrl(ResponseType responseType) {
        return getBaseAddress() + "/api2/" + (responseType == ResponseType.PNG ? "png" : "json");
    }

    /**
     * Address of the node, without the path of the API.
     *
     * @return scheme, host and port
     */
    protected String getBaseAddress() {
        return "https://" + getHostname() + ":" + getPort();
    }

    /**
     * Execute method GET
     *
     * @param resource   URL request
     * @param parameters Additional parameters
     * @return Result
     */
    public Result get(String resource, Map<String, Object> parameters) {
        return executeAction(resource, MethodType.GET, parameters);
    }

    /**
     * Execute method PUT
     *
     * @param resource   URL request
     * @param parameters Additional parameters
     * @return Result
     */
    public Result set(String resource, Map<String, Object> parameters) {
        return executeAction(resource, MethodType.SET, parameters);
    }

    /**
     * Execute method POST
     *
     * @param resource   URL request
     * @param parameters Additional parameters
     * @return Result
     */
    public Result create(String resource, Map<String, Object> parameters) {
        return executeAction(resource, MethodType.CREATE, parameters);
    }

    /**
     * Execute method DELETE
     *
     * @param resource   URL request
     * @param parameters Additional parameters
     * @return Result
     */
    public Result delete(String resource, Map<String, Object> parameters) {
        return executeAction(resource, MethodType.DELETE, parameters);
    }

    /**
     * Return Api Token
     *
     * @return String API token string
     */
    public String getApiToken() {
        return _apiToken;
    }

    /**
     * Set Api Token format USER@REALM!TOKENID=UUID
     *
     * @param apiToken API token string
     */
    public void setApiToken(String apiToken) {
        _apiToken = apiToken;
    }

    private void setToken(HttpURLConnection httpCon) {
        if (_ticketCSRFPreventionToken != null) {
            httpCon.setRequestProperty("CSRFPreventionToken", _ticketCSRFPreventionToken);
            httpCon.setRequestProperty("Cookie", "PVEAuthCookie=" + _ticketPVEAuthCookie);
        }

        if (_apiToken != null && !_apiToken.isEmpty()) {
            httpCon.setRequestProperty("Authorization", "PVEAPIToken " + _apiToken);
        }
    }

    private void setTimeouts(HttpURLConnection httpCon) {
        if (_timeout > 0) {
            // without the read timeout a node that accepts the connection and does not answer blocks forever
            httpCon.setConnectTimeout(_timeout);
            httpCon.setReadTimeout(_timeout);
        }
    }

    /**
     * Configure SSL context for a specific HTTPS connection (not global)
     *
     * @param httpsConn The HTTPS connection to configure
     */
    private void configureTrustAllSSL(HttpsURLConnection httpsConn) {
        if (!_validateCertificate) {
            try {
                // Create trust manager that trusts all certificates
                var trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        @Override
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }
                        @Override
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
                };

                // Create SSL context
                var sc = SSLContext.getInstance("TLS");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());

                // Apply to THIS connection only (not global)
                httpsConn.setSSLSocketFactory(sc.getSocketFactory());

                // Set hostname verifier for THIS connection only
                httpsConn.setHostnameVerifier((hostname, session) -> true);

            } catch (NoSuchAlgorithmException | KeyManagementException ex) {
                logger.log(Level.SEVERE, "Failed to configure SSL", ex);
            }
        }
    }

    /**
     * Build URL-encoded query string from parameters
     *
     * @param params Parameters to encode
     * @return URL-encoded query string
     */
    private String buildQueryString(Map<String, Object> params) {
        var query = new StringBuilder();
        params.forEach((key, value) -> {
            if (query.length() > 0) {
                query.append("&");
            }
            query.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
                 .append("=")
                 .append(URLEncoder.encode(value.toString(), StandardCharsets.UTF_8));
        });
        return query.toString();
    }

    /**
     * Read response from HTTP connection, handling both success and error streams
     *
     * @param httpCon HTTP connection
     * @param statusCode HTTP status code
     * @return Response body as it was sent
     * @throws IOException if reading fails
     */
    private byte[] readResponse(HttpURLConnection httpCon, int statusCode) throws IOException {
        // Choose the correct stream based on status code
        var stream = (statusCode >= 200 && statusCode < 400)
            ? httpCon.getInputStream()
            : httpCon.getErrorStream();

        if (stream == null) {
            return new byte[0];
        }

        try (stream) {
            return stream.readAllBytes();
        }
    }

    /**
     * Reason for a body that is not JSON (a proxy page, another service on that
     * port): it shows the start of the body.
     */
    private static String notJsonReason(int statusCode, String body) {
        var start = (body.length() > 100 ? body.substring(0, 100) + "\u2026" : body)
                .replaceAll("\\r\\n|\\r|\\n", " ")
                .trim();
        return "The answer is not JSON (HTTP " + statusCode + "): " + start;
    }

    private static boolean isSensitive(String name) {
        var lower = name.toLowerCase();
        for (var sensitive : SENSITIVE_NAMES) {
            if (lower.contains(sensitive)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Copy of an answer for the log, without the secrets it carries: the ticket
     * and the CSRF token of a login, the value of a new API token.
     */
    private static String maskSensitiveResponse(JsonNode response, String resource) {
        if (response == null) {
            return "null";
        }

        if (response.path("data").isObject()) {
            var copy = response.deepCopy();
            var data = (ObjectNode) copy.get("data");
            var names = new java.util.ArrayList<String>();
            data.fieldNames().forEachRemaining(names::add);
            for (var name : names) {
                if (isSensitive(name) || (name.equals("value") && resource.contains("/token"))) {
                    data.put(name, "****");
                }
            }
            return copy.toPrettyString();
        }

        return response.toPrettyString();
    }

    private Result executeAction(String resource, MethodType methodType, Map<String, Object> parameters) {
        return executeAction(resource, methodType, parameters, getResponseType());
    }

    private Result executeAction(String resource,
            MethodType methodType,
            Map<String, Object> parameters,
            ResponseType responseType) {
        // the url without the query string is the one written in the log
        var resourceUrl = getApiUrl(responseType) + resource;
        var url = resourceUrl;

        // decode http method
        var httpMethod = switch (methodType) {
            case GET -> "GET";
            case SET -> "PUT";
            case CREATE -> "POST";
            case DELETE -> "DELETE";
            default -> throw new AssertionError();
        };

        var params = new LinkedHashMap<String, Object>();
        if (parameters != null) {
            parameters.entrySet().stream().filter((entry) -> (entry.getValue() != null)).forEachOrdered((entry) -> {
                var value = entry.getValue();
                if (value instanceof Boolean) {
                    params.put(entry.getKey(), Boolean.TRUE.equals(value) ? 1 : 0);
                } else {
                    params.put(entry.getKey(), value);
                }
            });
        }

        if (logger.isLoggable(Level.FINE)) {
            logger.log(Level.FINE, "Method: {0}, Url: {1}", new Object[] { httpMethod, resourceUrl });
            if (!params.isEmpty()) {
                var paramsStr = new StringBuilder("Parameters:");
                params.forEach((key, value) -> paramsStr.append("\n  ")
                        .append(key)
                        .append(" : ")
                        .append(isSensitive(key) ? "****" : value));
                logger.fine(paramsStr.toString());
            }
        }

        var statusCode = 0;
        var reasonPhrase = "";
        JsonNode response = null;

        try {
            var hasBody = methodType == MethodType.SET || methodType == MethodType.CREATE;
            if (!hasBody && !params.isEmpty()) {
                url += "?" + buildQueryString(params);
            }

            var httpCon = (HttpURLConnection) URI.create(url).toURL().openConnection(_proxy);

            // Configure SSL for this connection only (not global)
            if (httpCon instanceof HttpsURLConnection httpsConn) {
                configureTrustAllSSL(httpsConn);
            }

            httpCon.setRequestMethod(httpMethod);
            setTimeouts(httpCon);
            setToken(httpCon);

            if (hasBody) {
                var data = objectMapper.writeValueAsString(params).getBytes(StandardCharsets.UTF_8);
                httpCon.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                httpCon.setDoOutput(true);
                httpCon.getOutputStream().write(data);
            }

            statusCode = httpCon.getResponseCode();
            reasonPhrase = httpCon.getResponseMessage();

            // Read response using the appropriate stream (success or error)
            var body = readResponse(httpCon, statusCode);

            if (body.length > 0) {
                if (responseType == ResponseType.PNG && statusCode == HttpURLConnection.HTTP_OK) {
                    response = objectMapper.createObjectNode()
                            .put("data", "data:image/png;base64," + Base64.getEncoder().encodeToString(body));
                } else {
                    // json, or the error answer of a png request
                    var text = new String(body, StandardCharsets.UTF_8);
                    try {
                        response = objectMapper.readTree(text);
                    } catch (JsonProcessingException ex) {
                        // not an answer of the API: keep the HTTP status (a success becomes
                        // 502, since the answer cannot be used) and show the start of the body
                        logger.log(Level.FINE, "The answer is not JSON", ex);
                        reasonPhrase = notJsonReason(statusCode, text);
                        if (statusCode >= 200 && statusCode <= 299) {
                            statusCode = HttpURLConnection.HTTP_BAD_GATEWAY;
                        }
                    }
                }
            }

        } catch (SocketTimeoutException ex) {
            logger.log(Level.SEVERE, "Request timed out", ex);
            statusCode = HttpURLConnection.HTTP_CLIENT_TIMEOUT;
            reasonPhrase = "Request timed out after " + _timeout + " ms: " + ex.getMessage();
            response = null;
        } catch (IOException ex) {
            // the request got no answer: name not resolved, connection refused, certificate refused
            logger.log(Level.SEVERE, "Error executing request", ex);
            statusCode = 0;
            reasonPhrase = ex.getClass().getSimpleName() + ": " + ex.getMessage();
            response = null;
        }

        _lastResult = new Result(response,
                statusCode,
                reasonPhrase,
                resource,
                parameters,
                methodType,
                responseType);

        if (logger.isLoggable(Level.FINER)) {
            logger.log(Level.FINER, """
                    Response: {0}
                    StatusCode: {1}
                    ReasonPhrase: {2}
                    IsSuccessStatusCode: {3}
                    =============================
                    """,
                    new Object[] {
                            maskSensitiveResponse(response, resource),
                            _lastResult.getStatusCode(),
                            _lastResult.getReasonPhrase(),
                            _lastResult.isSuccessStatusCode()
                    });
        } else if (logger.isLoggable(Level.FINE)) {
            logger.fine("=============================");
        }
        return _lastResult;
    }

    /**
     * Last result
     *
     * @return Result
     */
    public Result getLastResult() {
        return _lastResult;
    }

    /**
     * Add indexed parameter
     *
     * @param parameters Parameters map to add to
     * @param name       Name parameter to use as prefix
     * @param value      Values map with index as key
     */
    public static void addIndexedParameter(Map<String, Object> parameters, String name, Map<Integer, String> value) {
        if (value != null) {
            value.entrySet().forEach((entry) -> {
                parameters.put(name + entry.getKey(), entry.getValue());
            });
        }
    }

    /**
     * Wait for task to finish
     *
     * @param task    Task identifier
     * @param wait    Millisecond wait next check
     * @param timeOut Millisecond timeout
     * @return boolean True if the task is finished, false if it is still running
     *         at the timeout
     * @throws PveResultException if the status of the task cannot be read
     */
    public boolean waitForTaskToFinish(String task, long wait, long timeOut) {
        var isRunning = true;
        if (wait <= 0) {
            wait = 500;
        }
        if (timeOut < wait) {
            timeOut = wait + 5000;
        }

        var timeStart = System.currentTimeMillis();
        while (isRunning && (System.currentTimeMillis() - timeStart) < timeOut) {
            try {
                Thread.sleep(wait);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            isRunning = taskIsRunning(task);
        }

        // finished, also when the last check came after the timeout
        return !isRunning;
    }

    /**
     * Check task is running
     *
     * @param task Task identifier
     * @return boolean True if task is running, false otherwise
     * @throws PveResultException if the status of the task cannot be read
     */
    public boolean taskIsRunning(String task) {
        return ensureTaskStatus(readTaskStatus(task), task).get("status").asText().equals("running");
    }

    /**
     * Return exit status code task
     *
     * @param task Task identifier
     * @return String Exit status of the task ('OK', 'WARNINGS: n' or the error);
     *         null while the task is running
     * @throws PveResultException if the status of the task cannot be read
     */
    public String getExitStatusTask(String task) {
        var exitStatus = ensureTaskStatus(readTaskStatus(task), task).get("exitstatus");
        return exitStatus == null ? null : exitStatus.asText();
    }

    /**
     * Get node from task
     *
     * @param task Task identifier (UPID)
     * @return String Node of the task
     * @throws PveResultException if the task identifier is not valid
     */
    public static String getNodeFromTask(String task) {
        if (task == null || !task.matches("UPID:[^:]+:.*")) {
            throw new PveResultException(null, "'" + task + "' is not a valid task identifier (UPID)");
        }
        return task.split(":")[1];
    }

    /**
     * Read task status.
     *
     * @param task Task identifier to read status for
     * @return Result containing task status information
     */
    private Result readTaskStatus(String task) {
        return executeAction("/nodes/" + getNodeFromTask(task) + "/tasks/" + task + "/status",
                MethodType.GET,
                null,
                ResponseType.JSON);
    }

    /**
     * Data of a task status result, checked before it is read, so that an API
     * failure (node down, missing privilege) is reported with the HTTP status and
     * the Proxmox VE error instead of a NullPointerException.
     *
     * @param result result of the status read
     * @param task   task identifier
     * @return data of the task status
     * @throws PveResultException if the status of the task cannot be read
     */
    private static JsonNode ensureTaskStatus(Result result, String task) {
        if (result == null) {
            throw new PveResultException(null, "Read status of task '" + task + "' returned no result");
        }

        var inError = result.getResponse() != null && result.responseInError();
        var data = result.getData();
        if (inError || !result.isSuccessStatusCode() || data == null || data.isNull()) {
            var detail = inError ? result.getError()
                    : !result.isSuccessStatusCode() ? result.getReasonPhrase()
                    : "response does not contain 'data'";

            throw new PveResultException(result, "Read status of task '" + task + "' failed ("
                    + result.getStatusCode() + " " + result.getReasonPhrase() + "): " + detail);
        }

        return data;
    }
}
