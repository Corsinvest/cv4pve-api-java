/*
 * This file is part of the cv4pve-api-java https://github.com/Corsinvest/cv4pve-api-java,
 *
 * This source file is available under two different licenses:
 * - GNU General Public License version 3 (GPLv3)
 * - Corsinvest Enterprise License (CEL)
 * Full copyright and license information is available in
 * LICENSE.md which is distributed with this source code.
 *
 * Copyright (C) 2016 Corsinvest Srl	GPLv3 and CEL
 */
package it.corsinvest.proxmoxve.api;

import java.net.HttpURLConnection;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Result request API
 */
public class Result {

    private final String _reasonPhrase;
    private final int _statusCode;
    private final JSONObject _response;
    private final String _requestResource;
    private final Map<String, Object> _requestParameters;
    private final MethodType _methodType;
    private final ResponseType _responseType;

    protected Result(JSONObject response, int statusCode, String reasonPhrase, String requestResource,
            Map<String, Object> requestParameters, MethodType methodType, ResponseType responseType) {
        _response = response;
        _statusCode = statusCode;
        _reasonPhrase = reasonPhrase;
        _requestResource = requestResource;
        _requestParameters = requestParameters;
        _methodType = methodType;
        _responseType = responseType;
    }

    /**
     * Method type
     *
     * @return
     */
    public MethodType getMethodType() {
        return _methodType;
    }

    /**
     * Response Type
     *
     * @return
     */
    public ResponseType getResponseType() {
        return _responseType;
    }

    /**
     * Resource request
     *
     * @return
     */
    public String getRequestResource() {
        return _requestResource;
    }

    /**
     * Request parameter
     *
     * @return
     */
    public Map<String, Object> getRequestParameters() {
        return _requestParameters;
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
        return !_response.isNull("errors");
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
                ret.append(name).append(" : ").append(errors.get(name));
            }
        }
        return ret.toString();
    }
}
