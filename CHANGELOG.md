# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The major and minor version follow Proxmox VE (9.2.x targets Proxmox VE 9.2); the patch number can include breaking changes, listed under "Changed (breaking)".

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
