package it.corsinvest.proxmoxve.api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
public class ClientBase {

    private String _ticketCSRFPreventionToken;
    private String _ticketPVEAuthCookie;
    private final String _hostname;
    private final int _port;
    private int _debugLevel;
    private Result _lastResult;

    public ClientBase(String hostname, int port) {
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
     * Creation ticket from login.
     *
     * @param userName user name or &lt;username&gt;@&lt;realm&gt;
     * @param password password connection
     * @return
     * @throws JSONException
     */
    public boolean login(String userName, String password) throws JSONException {
        String realm = "pam";
        String[] data = userName.split("@");
        if (data.length > 1) {
            userName = data[0];
            realm = data[1];
        }

        return login(userName, password, realm);
    }

    /**
     * Creation ticket from login.
     *
     * @param userName user name
     * @param password password connection
     * @param realm pam/pve or custom
     * @return
     * @throws JSONException
     */
    public boolean login(String userName, String password, String realm) throws JSONException {
        Result result = create("/access/ticket",
                new HashMap<String, Object>() {
            {
                put("password", password);
                put("username", userName);
                put("otp", null);
                put("path", null);
                put("privs", null);
                put("realm", realm);
            }
        });

        if (result.isSuccessStatusCode()) {
            _ticketCSRFPreventionToken = result.getResponse().getJSONObject("data").getString("CSRFPreventionToken");
            _ticketPVEAuthCookie = result.getResponse().getJSONObject("data").getString("ticket");
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns the base URL used to interact with the Proxmox VE API.
     *
     * @return The proxmox API URL.
     */
    public String getApiUrl() {
        return "https://" + getHostname() + ":" + getPort() + "/api2/json";
    }

    private enum HttpMethod {
        GET, POST, PUT, DELETE
    }

    /**
     * Execute method GET
     *
     * @param resource Url request
     * @param parameters Additional parameters
     * @return Result
     * @throws JSONException
     */
    public Result get(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, HttpMethod.GET, parameters);
    }

    /**
     * Execute method PUT
     *
     * @param resource Url request
     * @param parameters Additional parameters
     * @return Result
     * @throws JSONException
     */
    public Result set(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, HttpMethod.PUT, parameters);
    }

    /**
     * Execute method POST
     *
     * @param resource Url request
     * @param parameters Additional parameters
     * @return Result
     * @throws JSONException
     */
    public Result create(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, HttpMethod.POST, parameters);
    }

    /**
     * Execute method DELETE
     *
     * @param resource Url request
     * @param parameters Additional parameters
     * @return Result
     * @throws JSONException
     */
    public Result delete(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, HttpMethod.DELETE, parameters);
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
     * @return
     */
    public int getDebugLevel() {
        return _debugLevel;
    }

    private void setToken(HttpURLConnection httpCon) {
        if (_ticketCSRFPreventionToken != null) {
            httpCon.setRequestProperty("CSRFPreventionToken", _ticketCSRFPreventionToken);
            httpCon.setRequestProperty("Cookie", "PVEAuthCookie=" + _ticketPVEAuthCookie);
        }
    }

    private Result executeAction(String resource, HttpMethod method, Map<String, Object> parameters) throws JSONException {
        String url = getApiUrl() + resource;

        Map params = new LinkedHashMap<>();
        if (parameters != null) {
            parameters.entrySet().stream().filter((entry) -> (entry.getValue() != null)).forEachOrdered((entry) -> {
                String value = entry.getValue().toString();
                if (entry.getValue() instanceof Boolean) {
                    value = ((Boolean) entry.getValue()) ? "1" : "0";
                }
                params.put(entry.getKey(), value);
            });
        }

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
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

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
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
            switch (method) {
                case GET: {
                    if (!params.isEmpty()) {
                        StringBuilder urlParams = new StringBuilder();
                        params.forEach((key, value) -> {
                            try {
                                urlParams.append(urlParams.length() > 0 ? "&" : "")
                                        .append(key)
                                        .append("=")
                                        .append(URLEncoder.encode((String) value, "UTF-8"));
                            } catch (UnsupportedEncodingException ex) {
                                Logger.getLogger(ClientBase.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        });
                        url += "?" + urlParams.toString();
                    }

                    httpCon = (HttpURLConnection) new URL(url).openConnection();
                    httpCon.setRequestMethod("GET");
                    setToken(httpCon);
                    break;
                }

                case PUT:
                case POST: {
                    StringBuilder postData = new StringBuilder();
                    params.forEach((key, value) -> {
                        postData.append(postData.length() > 0 ? "&" : "")
                                .append(key)
                                .append("=")
                                .append(value);
                    });

                    byte[] postDataBytes = postData.toString().getBytes("UTF-8");
                    httpCon = (HttpURLConnection) new URL(url).openConnection();
                    httpCon.setRequestMethod(method + "");
                    httpCon.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                    httpCon.setRequestProperty("Content-Length", String.valueOf(postDataBytes.length));
                    setToken(httpCon);

                    httpCon.setDoOutput(true);
                    httpCon.getOutputStream().write(postDataBytes);

                    break;
                }

                case DELETE: {
                    httpCon = (HttpURLConnection) new URL(url).openConnection();
                    httpCon.setRequestMethod("DELETE");
                    setToken(httpCon);
                    break;
                }
            }

            //httpCon.setRequestProperty("User-Agent", "Mozilla/5.0");
            if (getDebugLevel() >= 1) {
                System.out.println("Method: " + method + " , Url: " + url);
                if (method != HttpMethod.GET) {
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
                response = new JSONObject(sb.toString());
            }
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

        _lastResult = new Result(response, statusCode, reasonPhrase);
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
     * @return
     */
    public Result getLastResult() {
        return _lastResult;
    }

    /**
     * Add indexed parameter
     *
     * @param parameters Parameters
     * @param name Name parameter
     * @param value Calues
     */
    public static void addIndexedParameter(Map<String, Object> parameters, String name, Map<Integer, String> value) {
        value.entrySet().forEach((entry) -> {
            parameters.put(name + entry.getKey(), entry.getValue());
        });
    }

    /**
     * Wait for task to finish
     *
     * @param node Node identifier
     * @param task Task identifier
     * @param wait Millisecond wait next check
     * @param timeOut Millisecond timeout
     * @throws JSONException
     */
    public void waitForTaskToFinish(String node, String task, long wait, long timeOut) throws JSONException {
        Boolean isRunning = true;
        if (wait <= 0) {
            wait = 500;
        }
        if (timeOut < wait) {
            timeOut = wait + 5000;
        }
        long timeStart = System.currentTimeMillis();
        long waitTime = System.currentTimeMillis();
        while (isRunning && (timeStart - System.currentTimeMillis()) < timeOut) {
            if ((System.currentTimeMillis() - waitTime) >= wait) {
                waitTime = System.currentTimeMillis();
                isRunning = taskIsRunning(node, task);
            }
        }
    }

    /**
     * Cherck task is running
     *
     * @param node Node identifier
     * @param task Task identifier
     * @return
     * @throws JSONException
     */
    public boolean taskIsRunning(String node, String task) throws JSONException {
        return readTaskStatus(node, task).getResponse().getJSONObject("data").getString("status").equals("running");
    }

    /**
     * Return exit status code task
     *
     * @param node Node identifier
     * @param task Task identifier
     * @return
     * @throws JSONException
     */
    public String getExitStatusTask(String node, String task) throws JSONException {
        return readTaskStatus(node, task).getResponse().getJSONObject("data").getString("exitstatus");
    }

    public static <T> List<T> JSONArrayToList(JSONArray array) throws JSONException {
        List<T> ret = new ArrayList<>();
        if (array != null) {
            for (int i = 0; i < array.length(); i++) {
                ret.add((T) array.get(i));
            }
        }
        return ret;
    }

    /**
     * Read task status.
     *
     * @return Result
     * @throws JSONException
     */
    private Result readTaskStatus(String node, String task) throws JSONException {
        return get("/nodes/" + node + "/tasks/" + task + "/status", null);
    }

}
