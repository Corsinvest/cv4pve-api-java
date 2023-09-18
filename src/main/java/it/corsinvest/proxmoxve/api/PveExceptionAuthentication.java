/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: GPL-3.0-only
 */
package it.corsinvest.proxmoxve.api;

/**
 * Pve Exception Authentication
 */
public class PveExceptionAuthentication extends Exception {

    private final Result _result;

    /**
     * Constructor
     *
     * @param result
     * @param errorMessage
     */
    public PveExceptionAuthentication(Result result, String errorMessage) {
        super(errorMessage);
        _result = result;
    }

    /**
     * Get result
     *
     * @return
     */
    public Result getResult() {
        return _result;
    }
}
