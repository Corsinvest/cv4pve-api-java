/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: GPL-3.0-only
 */

package it.corsinvest.proxmoxve.api;

/**
 * Enumerates the possible response types from the Proxmox VE API.
 * This helps in parsing and handling different types of API responses
 * depending on the operation that was performed.
 */
public enum ResponseType {
    /**
     * JSON response type for standard API responses containing structured data.
     */
    JSON,

    /**
     * PNG response type for image data responses, such as console screenshots.
     */
    PNG
}
