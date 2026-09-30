/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */
package it.corsinvest.proxmoxve.api;

/**
 * Call to the Proxmox VE API that did not return the expected result, e.g. the
 * status of a task that cannot be read.
 */
public class PveResultException extends RuntimeException {

    private final transient Result _result;

    /**
     * Constructor
     *
     * @param result       result of the call, can be null
     * @param errorMessage message
     */
    public PveResultException(Result result, String errorMessage) {
        super(errorMessage);
        _result = result;
    }

    /**
     * Get result
     *
     * @return result of the call, can be null
     */
    public Result getResult() {
        return _result;
    }
}
