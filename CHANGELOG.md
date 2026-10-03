# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The major and minor version follow Proxmox VE (9.2.x targets Proxmox VE 9.2); the patch number can include breaking changes, listed under "Changed (breaking)".

## [9.2.3] - 2026-10-03

### Added
- Tests: offline JUnit tests on a local server that plays the part of Proxmox VE, run by `mvn test` and by the build workflow; tests on a real Proxmox VE tagged `live`, run with `mvn test -P live` (`PVE_HOST`, `PVE_API_TOKEN`, `PVE_TEST_VMID`). The old `Test` program and the exec plugin are removed ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))

### Changed
- A request that times out gives a `Result` with status 408; a success status with a body that is not JSON (for example the page of a proxy) gives status 502 with the start of the body in the reason, instead of a success without data ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- A request without an answer (connection refused, name not resolved, certificate refused) keeps status 0 and has the exception in the reason ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- `getApiUrl()` follows the response type (`/api2/json` or `/api2/png`); new protected `getBaseAddress()` gives scheme, host and port ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- Bump `jackson-databind`, `jackson-core`, `jackson-annotations` from 2.18.10 to 2.18.11 ([#36](https://github.com/Corsinvest/cv4pve-api-java/pull/36))

### Fixed
- DELETE requests dropped their parameters: they are now sent in the query string (for example `delsnapshot(force)`, `deleteRouteMapEntry(lock_token)`) ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- The timeout was applied only to the connection: a node that accepted the connection and did not answer blocked the call, and the wait for a task, forever. It is now also the read timeout ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- PNG response type: the image was corrupted (read as text) and the request went to `/api2/json`. The bytes are returned as they are and the request goes to `/api2/png`; login and task status are always read as JSON ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- `Result.responseInError()` and `getError()` threw `NullPointerException` when there was no response ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- `login` threw `NullPointerException` on an answer without data or without a ticket; it now returns `false`. The realm is read after the last `@` ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- A task id that is not valid (null, empty, not a UPID) gave `NullPointerException` or `ArrayIndexOutOfBoundsException`; it is now a `PveResultException` before any request ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- Debug log: the ticket and the CSRF token of the login answer (`FINER`) and the query string of GET and DELETE requests (`FINE`) were printed unmasked ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))
- `Content-Length` was the number of characters, not of bytes: the header is now set by the JDK ([#37](https://github.com/Corsinvest/cv4pve-api-java/pull/37))

## [9.2.2] - 2026-10-02

### Added
- Api: Ceph health mute, `getCluster().getCeph().getHealthMute()`: `healthMuteIndex()` and `get(code).healthMute(value, sticky, ttl)` ([#34](https://github.com/Corsinvest/cv4pve-api-java/pull/34))
- Api: Ceph rolling restart, `restartBulk` on `/cluster/ceph/restart-bulk` and `/nodes/{node}/ceph/restart-bulk` ([#34](https://github.com/Corsinvest/cv4pve-api-java/pull/34))
- Api: Ceph releases, `releases()` on `/nodes/{node}/ceph/releases` ([#34](https://github.com/Corsinvest/cv4pve-api-java/pull/34))
- Api: `/nodes/{node}/journal` `journal` has the new filters `identifiers`, `kernel`, `priority`, `service`, `structured`, `unit`, `units` ([#34](https://github.com/Corsinvest/cv4pve-api-java/pull/34))

### Changed (breaking)
- Api: path parameters no longer repeated as method arguments: drop `route_map_id` from `getRouteMapEntry`, `deleteRouteMapEntry`, `updateRouteMapEntry`, `listRouteMapEntriesForRouteMap` and `pci_id_or_mapping` from `pciIndex`, `mdevscan`. The value comes from `get(...)` ([#34](https://github.com/Corsinvest/cv4pve-api-java/pull/34))
- Api: `asn`, `level`, `seq` are `Long` instead of `Integer` (up to 4294967295) ([#34](https://github.com/Corsinvest/cv4pve-api-java/pull/34))
- Api: `/cluster/ha/rules` parameter order changed, and the arguments are all `String`, so old calls compile and send the wrong values: `createRule(rule, type, resources, ...)` was `createRule(resources, rule, type, ...)`; `updateRule(type, delete, digest, affinity, comment, ...)` was `updateRule(type, affinity, comment, delete, digest, ...)` ([#34](https://github.com/Corsinvest/cv4pve-api-java/pull/34))

### Changed
- `getExitStatusTask` returns null while the task runs ([#33](https://github.com/Corsinvest/cv4pve-api-java/pull/33))
- Bump `jackson-databind` from 2.18.9 to 2.18.10 ([#32](https://github.com/Corsinvest/cv4pve-api-java/pull/32))
- CI: the GitHub release body is the section of `CHANGELOG.md` for the tag version ([#34](https://github.com/Corsinvest/cv4pve-api-java/pull/34))
- CI: workflow permissions and job timeouts declared ([#31](https://github.com/Corsinvest/cv4pve-api-java/pull/31))

### Fixed
- Login with a second factor never worked on Proxmox VE 7+ (TOTP, WebAuthn, recovery keys): the answer to the challenge is now sent in a second call with `tfa-challenge`; a code without a type is sent as `totp:<code>`. `tfa-challenge` is masked in the debug log ([#33](https://github.com/Corsinvest/cv4pve-api-java/pull/33))
- `waitForTaskToFinish` returns true when the task is finished, also when the last check came after the timeout, and no longer waits after the task is finished ([#33](https://github.com/Corsinvest/cv4pve-api-java/pull/33))
- `taskIsRunning`, `getExitStatusTask`: a status that cannot be read (node down, missing privilege) throws `PveResultException` with the HTTP status and the Proxmox VE error, instead of a `NullPointerException` ([#33](https://github.com/Corsinvest/cv4pve-api-java/pull/33))

## [9.2.1] and earlier

See [GitHub releases](https://github.com/Corsinvest/cv4pve-api-java/releases).
