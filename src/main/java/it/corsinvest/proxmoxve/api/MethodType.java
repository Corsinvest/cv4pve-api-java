/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: GPL-3.0-only
 */

package it.corsinvest.proxmoxve.api;

/**
 * Enumerates the HTTP method types supported by the Proxmox VE API.
 * These correspond to different types of operations that can be performed
 * on resources in the Proxmox VE system.
 */
public enum MethodType {
    /**
     * GET method for retrieving resource information.
     * Used for read-only operations that fetch data from the API.
     */
    GET,

    /**
     * SET method for creating or updating resources.
     * Used for operations that modify existing resources or create new ones
     * using PUT or POST HTTP methods.
     */
    SET,

    /**
     * CREATE method for creating new resources.
     * Specifically used for POST operations that create new entities
     * in the Proxmox VE system.
     */
    CREATE,

    /**
     * DELETE method for removing resources.
     * Used for operations that delete existing resources from the system.
     */
    DELETE
}
