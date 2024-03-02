/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: GPL-3.0-only
 */
package it.corsinvest.proxmoxve.api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Proxmox VE Client Base
 */
public class PveClientBase {

    private String _ticketCSRFPreventionToken;
    private String _ticketPVEAuthCookie;
    private final String _hostname;
    private final int _port;
    private int _debugLevel;
    private Result _lastResult;
    private ResponseType _responseType = ResponseType.JSON;
    private String _apiToken;
    private Proxy _proxy = Proxy.NO_PROXY;
    private int _timeout = 0;

    public PveClientBase(String hostname, int port) {
        _hostname = hostname;
        _port = port;
    }

    /**
     * Gets the hostname configured.
     *
     * @return string The hostname.
     */
    public String getHostname() {
        return _hostname;
    }

    /**
     * Gets the port configured.
     *
     * @return int The port.
     */
    public int getPort() {
        return _port;
    }

    /**
     * Get proxy
     *
     * @return Proxy
     */
    public Proxy getProxy() {
        return _proxy;
    }

    /**
     * Set proxy
     *
     * @return Proxy
     */
    public void setProxy(Proxy proxy) {
        _proxy = proxy;
    }

    /**
     * Get the response type that is going to be returned when doing requests
     * (json, png).
     *
     * @return ResponseType
     */
    public ResponseType getResponseType() {
        return _responseType;
    }

    /**
     * Set the response type that is going to be returned when doing requests
     * (json, png).
     *
     * @param responseType Response type
     */
    public void setResponseType(ResponseType responseType) {
        _responseType = responseType;
    }

    /**
     * Set timeout connection
     *
     * @param timeout
     */
    public void setTimeout(int timeout) {
        if (timeout < 0) {
            throw new IllegalArgumentException("timeout can not be negative");
        }
        _timeout = timeout;
    }

    /**
     * Return timeout connection
     *
     * @return
     */
    public int getTimeout() {
        return _timeout;
    }

    /**
     * Creation ticket from login.
     *
     * @param username user name or &lt;username&gt;@&lt;realm&gt;
     * @param password password connection
     * @return boolean
     * @throws JSONException
     * @throws PveExceptionAuthentication
     */
    public boolean login(String username, String password) throws JSONException, PveExceptionAuthentication {
        String realm = "pam";
        String[] data = username.split("@");
        if (data.length > 1) {
            username = data[0];
            realm = data[1];
        }

        return login(username, password, realm, null);
    }

    /**
     * Creation ticket from login.
     *
     * @param username user name
     * @param password password connection
     * @param realm    pam/pve or custom
     *
     * @return boolean
     * @throws JSONException
     * @throws PveExceptionAuthentication
     */
    public boolean login(String username, String password, String realm)
            throws JSONException, PveExceptionAuthentication {
        return login(username, password, realm, null);
    }

    /**
     * Creation ticket from login.
     *
     * @param username user name
     * @param password password connection
     * @param realm    pam/pve or custom
     * @param otp      One-time password for Two-factor authentication.
     *
     * @return boolean
     * @throws JSONException
     * @throws PveExceptionAuthentication
     */
    public boolean login(String username, String password, String realm, String otp)
            throws JSONException, PveExceptionAuthentication {
        Result result = create("/access/ticket", new HashMap<String, Object>() {
            {
                put("password", password);
                put("username", username);
                put("realm", realm);
                put("otp", otp);
            }
        });

        if (result.isSuccessStatusCode()) {
            if (result.getResponse().getJSONObject("data").has("NeedTFA")) {
                throw new PveExceptionAuthentication(result,
                        "Couldn't authenticate user: missing Two Factor Authentication (TFA)");
            }

            _ticketCSRFPreventionToken = result.getResponse().getJSONObject("data").getString("CSRFPreventionToken");
            _ticketPVEAuthCookie = result.getResponse().getJSONObject("data").getString("ticket");
        }
        return result.isSuccessStatusCode();
    }

    /**
     * Returns the base URL used to interact with the Proxmox VE API.
     *
     * @return The proxmox API URL.
     */
    public String getApiUrl() {
        return "https://" + getHostname() + ":" + getPort() + "/api2/json";
    }

    /**
     * Execute method GET
     *
     * @param resource   Url request
     * @param parameters Additional parameters
     * @return Result
     * @throws JSONException
     */
    public Result get(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, MethodType.GET, parameters);
    }

    /**
     * Execute method PUT
     *
     * @param resource   Url request
     * @param parameters Additional parameters
     * @return Result
     * @throws JSONException
     */
    public Result set(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, MethodType.SET, parameters);
    }

    /**
     * Execute method POST
     *
     * @param resource   Url request
     * @param parameters Additional parameters
     * @return Result
     * @throws JSONException
     */
    public Result create(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, MethodType.CREATE, parameters);
    }

    /**
     * Execute method DELETE
     *
     * @param resource   Url request
     * @param parameters Additional parameters
     * @return Result
     * @throws JSONException
     */
    public Result delete(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, MethodType.DELETE, parameters);
    }

    /**
     * Set debug level
     *
     * @param value 0 - nothing 1 - Url and method 2 - Url and method and result
     */
    public void setDebugLevel(int value) {
        _debugLevel = value;
    }

    /**
     * Return debug level.
     *
     * @return int
     */
    public int getDebugLevel() {
        return _debugLevel;
    }

    /**
     * Return Api Token
     *
     * @return String
     */
    public String getApiToken() {
        return _apiToken;
    }

    /**
     * Set Api Token format USER@REALM!TOKENID=UUID
     *
     * @param apiToken
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

    private void setConnectionTimeout(HttpURLConnection httpCon) {
        if (_timeout > 0) {
            httpCon.setConnectTimeout(_timeout);
        }
    }

    private Result executeAction(String resource, MethodType methodType, Map<String, Object> parameters)
            throws JSONException {
        String url = getApiUrl() + resource;

        // decode http method
        String httpMethod = "";
        switch (methodType) {
            case GET:
                httpMethod = "GET";
                break;
            case SET:
                httpMethod = "PUT";
                break;
            case CREATE:
                httpMethod = "POST";
                break;
            case DELETE:
                httpMethod = "DELETE";
                break;
            default:
                throw new AssertionError();
        }

        Map<String, Object> params = new LinkedHashMap<>();
        if (parameters != null) {
            parameters.entrySet().stream().filter((entry) -> (entry.getValue() != null)).forEachOrdered((entry) -> {
                Object value = entry.getValue();
                if (value instanceof Boolean) {
                    params.put(entry.getKey(), Boolean.TRUE.equals(value) ? 1 : 0);
                } else {
                    params.put(entry.getKey(), value);
                }
            });
        }

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
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
        } };

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            Logger.getLogger(PveClientBase.class.getName()).log(Level.SEVERE, null, ex);
        }

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = (String hostname, SSLSession session) -> true;

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        int statusCode = 0;
        String reasonPhrase = "";
        JSONObject response = new JSONObject();
        HttpURLConnection httpCon = null;

        try {
            switch (methodType) {
                case GET: {
                    if (!params.isEmpty()) {
                        StringBuilder urlParams = new StringBuilder();
                        params.forEach((key, value) -> {
                            urlParams.append(urlParams.length() > 0 ? "&" : "")
                                    .append(key)
                                    .append("=")
                                    .append(value.toString());
                        });
                        url += "?" + urlParams.toString();
                    }

                    httpCon = (HttpURLConnection) new URL(url).openConnection(_proxy);
                    httpCon.setRequestMethod("GET");
                    setConnectionTimeout(httpCon);
                    setToken(httpCon);
                    break;
                }

                case SET:
                case CREATE: {
                    String data = new JSONObject(params).toString();
                    httpCon = (HttpURLConnection) new URL(url).openConnection(_proxy);
                    httpCon.setRequestMethod(httpMethod);
                    httpCon.setRequestProperty("Content-Type", "application/json");
                    httpCon.setRequestProperty("Content-Length", String.valueOf(data.length()));
                    setConnectionTimeout(httpCon);
                    setToken(httpCon);

                    httpCon.setDoOutput(true);
                    httpCon.getOutputStream().write(data.getBytes("UTF-8"));
                    break;
                }

                case DELETE: {
                    httpCon = (HttpURLConnection) new URL(url).openConnection(_proxy);
                    httpCon.setRequestMethod("DELETE");
                    setConnectionTimeout(httpCon);
                    setToken(httpCon);
                    break;
                }
            }

            if (getDebugLevel() >= 1) {
                System.out.println("Method: " + httpMethod + " , Url: " + url);
                if (methodType != MethodType.GET) {
                    System.out.println("Parameters:");
                    params.forEach((key, value) -> {
                        System.out.println(key + " : " + value);
                    });
                }
            }

            statusCode = httpCon.getResponseCode();
            reasonPhrase = httpCon.getResponseMessage();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(httpCon.getInputStream()))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }

                switch (getResponseType()) {
                    case JSON:
                        response = new JSONObject(sb.toString());
                        break;

                    case PNG:
                        response = new JSONObject("data:image/png;base64,"
                                + new String(Base64.getEncoder().encode(sb.toString().getBytes())));
                        break;

                    default:
                        throw new AssertionError();
                }

            }
        } catch (IOException ex) {
            Logger.getLogger(PveClientBase.class.getName()).log(Level.SEVERE, null, ex);
        }

        _lastResult = new Result(response,
                statusCode,
                reasonPhrase,
                resource,
                parameters,
                methodType,
                getResponseType());

        if (getDebugLevel() >= 2) {
            System.out.println(response.toString(2));
            System.out.println("StatusCode:          " + _lastResult.getStatusCode());
            System.out.println("ReasonPhrase:        " + _lastResult.getReasonPhrase());
            System.out.println("IsSuccessStatusCode: " + _lastResult.isSuccessStatusCode());
        }
        if (getDebugLevel() > 0) {
            System.out.println("=============================");
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
     * @param parameters Parameters
     * @param name       Name parameter
     * @param value      Values
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
     * @return 0 Success
     * @throws JSONException
     */
    public boolean waitForTaskToFinish(String task, long wait, long timeOut) throws JSONException {
        boolean isRunning = true;
        if (wait <= 0) {
            wait = 500;
        }
        if (timeOut < wait) {
            timeOut = wait + 5000;
        }

        long timeStart = System.currentTimeMillis();
        long waitTime = System.currentTimeMillis();
        while (isRunning && (System.currentTimeMillis() - timeStart) < timeOut) {
            if ((System.currentTimeMillis() - waitTime) >= wait) {
                waitTime = System.currentTimeMillis();
                isRunning = taskIsRunning(task);
            }
        }

        return System.currentTimeMillis() - timeStart < timeOut;
    }

    /**
     * Check task is running
     *
     * @param task Task identifier
     * @return boolean
     * @throws JSONException
     */
    public boolean taskIsRunning(String task) throws JSONException {
        return readTaskStatus(task).getResponse().getJSONObject("data").getString("status").equals("running");
    }

    /**
     * Return exit status code task
     *
     * @param task Task identifier
     * @return String
     * @throws JSONException
     */
    public String getExitStatusTask(String task) throws JSONException {
        return readTaskStatus(task).getResponse().getJSONObject("data").getString("exitstatus");
    }

    /**
     * Convert JSONArray To List
     *
     * @param <T>   Type of data
     * @param array Array JSON
     * @return T List of Type of data
     * @throws JSONException
     */
    public static <T> List<T> JSONArrayToList(JSONArray array) throws JSONException {
        ArrayList<T> ret = new ArrayList<T>();
        if (array != null) {
            for (int i = 0; i < array.length(); i++) {
                ret.add((T) array.get(i));
            }
        }
        return ret;
    }

    /**
     * Get node from task
     *
     * @param task Task
     * @return String
     */
    public static String getNodeFromTask(String task) {
        return task.split(":")[1];
    }

    /**
     * Read task status.
     *
     * @param task
     * @return Result
     * @throws JSONException
     */
    private Result readTaskStatus(String task) throws JSONException {
        return get("/nodes/" + getNodeFromTask(task) + "/tasks/" + task + "/status", null);
    }
}
