package it.corsinvest.proxmoxve.api;

import java.net.HttpURLConnection;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Result request API
 */
public class Result {

    private final String _reasonPhrase;
    private final int _statusCode;
    private final JSONObject _response;

    protected Result(JSONObject respose, int statusCode, String reasonPhrase) {
        _response = respose;
        _statusCode = statusCode;
        _reasonPhrase = reasonPhrase;
    }

    /**
     * Gets the reason phrase which typically is sent by servers together with
     * the status code.
     *
     * @return
     */
    public String getReasonPhrase() {
        return _reasonPhrase;
    }

    /**
     * Contains the values of status codes defined for HTTP.
     *
     * @return
     */
    public int getStatusCode() {
        return _statusCode;
    }

    /**
     * Gets a value that indicates if the HTTP response was successful.
     *
     * @return
     */
    public boolean isSuccessStatusCode() {
        return _statusCode == HttpURLConnection.HTTP_OK;
    }

    /**
     * Proxmox VE response.
     *
     * @return JSONObject
     */
    public JSONObject getResponse() {
        return _response;
    }

    /**
     * Get if response Proxmox VE contain errors
     *
     * @return
     * @throws org.json.JSONException
     */
    public boolean responseInError() throws JSONException {
        return !_response.isNull("errorr");
    }

    /**
     * Get error
     *
     * @return
     * @throws org.json.JSONException
     */
    public String getError() throws JSONException {
        StringBuilder ret = new StringBuilder();
        if (responseInError()) {
            JSONObject errors = _response.getJSONObject("errors");
            for (int i = 0; i < errors.names().length(); i++) {
                if (ret.length() > 0) {
                    ret.append("\n");
                }

                String name = errors.names().getString(i);
                ret.append(name)
                        .append(" : ")
                        .append(errors.get(name));
            }
        }
        return ret.toString();
    }
}
