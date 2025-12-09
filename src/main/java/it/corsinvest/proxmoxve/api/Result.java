/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: GPL-3.0-only
 */
package it.corsinvest.proxmoxve.api;

import java.net.HttpURLConnection;
import java.util.Map;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * Result request API
 */
public class Result {

    private final String _reasonPhrase;
    private final int _statusCode;
    private final JsonNode _response;
    private final String _requestResource;
    private final Map<String, Object> _requestParameters;
    private final MethodType _methodType;
    private final ResponseType _responseType;

    protected Result(JsonNode response,
            int statusCode,
            String reasonPhrase,
            String requestResource,
            Map<String, Object> requestParameters,
            MethodType methodType,
            ResponseType responseType) {
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
     * @return JsonNode
     */
    public JsonNode getResponse() {
        return _response;
    }

    /**
     * Get the data field from the response.
     *
     * @return JsonNode representing the data field, or null if not present
     */
    public JsonNode getData() {
        return _response != null ? _response.get("data") : null;
    }

    /**
     * Get if response Proxmox VE contain errors
     *
     * @return
     */
    public boolean responseInError() {
        return _response.has("errors") && !_response.get("errors").isNull();
    }

    /**
     * Get error
     *
     * @return
     */
    public String getError() {
        var ret = new StringBuilder();
        if (responseInError()) {
            var errors = _response.get("errors");
            if (errors.isObject()) {
                errors.fieldNames().forEachRemaining(fieldName -> {
                    if (ret.length() > 0) {
                        ret.append("\n");
                    }
                    ret.append(fieldName).append(" : ").append(errors.get(fieldName).asText());
                });
            }
        }
        return ret.toString();
    }
}
