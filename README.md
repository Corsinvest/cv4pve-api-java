# <img src="https://raw.githubusercontent.com/Corsinvest/cv4pve-api-java/master/icon.svg" alt="" height="36" align="top"> cv4pve-api-java

```
   ______                _                      __
  / ____/___  __________(_)___ _   _____  _____/ /_
 / /   / __ \/ ___/ ___/ / __ \ | / / _ \/ ___/ __/
/ /___/ /_/ / /  (__  ) / / / / |/ /  __(__  ) /_
\____/\____/_/  /____/_/_/ /_/|___/\___/____/\__/

Proxmox VE API Client for Java (Made in Italy)
```

[![License](https://img.shields.io/github/license/Corsinvest/cv4pve-api-java.svg?style=flat-square)](https://github.com/Corsinvest/cv4pve-api-java/blob/master/LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-blue?style=flat-square&logo=openjdk)](https://openjdk.org/)
[![Maven Central](https://img.shields.io/maven-metadata/v.svg?metadataUrl=https%3A%2F%2Frepo1.maven.org%2Fmaven2%2Fit%2Fcorsinvest%2Fproxmoxve%2Fcv4pve-api-java%2Fmaven-metadata.xml&label=maven-central&style=flat-square)](https://central.sonatype.com/artifact/it.corsinvest.proxmoxve/cv4pve-api-java)

> **The Proxmox VE API from Java**: a client with a method for every endpoint of the Proxmox VE API, running in your application and talking only to the API.
>
> **[Documentation](https://corsinvest.github.io/cv4pve-api-java/)**

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Corsinvest/cv4pve-api-java/master/docs/src/assets/java.svg" alt="Java logo" width="70">
</p>

## Why

An application that manages Proxmox VE (a customer portal, a scheduled job, a monitoring or billing tool) has to speak its REST API: tickets and tokens, paths, parameters, JSON, tasks that end later. Written by hand it is a layer of HTTP code to build and to keep up with every Proxmox VE release.

cv4pve-api-java is that layer, generated from the API itself. The calls follow the tree of the API, so the [Proxmox VE API viewer](https://pve.proxmox.com/pve-docs/api-viewer/) is also the reference of the client.

It **runs in your application and uses only the Proxmox VE API**: nothing to install on the nodes, no SSH.

---

## Features

- **The whole API**: a method for every endpoint and HTTP method, generated from the Proxmox VE API schema; `/nodes/{node}/qemu/{vmid}/config` is `client.getNodes().get("pve01").getQemu().get(100).getConfig()`.
- **One Result for every call**: the HTTP outcome and the Proxmox VE data, read as a Jackson `JsonNode`. A failed call does not throw.
- **API token or password**: with two-factor authentication, certificate validation, timeout and proxy.
- **Tasks**: start a backup, a clone or a migration, wait for its task and read whether it succeeded.
- **Raw calls**: GET, POST, PUT and DELETE on any path with a map of parameters, for the calls with many options and for endpoints newer than the library.
- **One dependency**: Java 17 or later and Jackson, on Windows, Linux and macOS.

---

## Quick start

Maven:

```xml
<dependency>
    <groupId>it.corsinvest.proxmoxve</groupId>
    <artifactId>cv4pve-api-java</artifactId>
    <version>9.2.3</version>
</dependency>
```

Gradle:

```groovy
implementation 'it.corsinvest.proxmoxve:cv4pve-api-java:9.2.3'
```

```java
import it.corsinvest.proxmoxve.api.PveClient;

// connect to any node of the cluster, with an API token
var client = new PveClient("pve01", 8006);
client.setApiToken("automation@pve!app=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

// GET /nodes/{node}/qemu/{vmid}/status/current
var result = client.getNodes().get("pve01").getQemu().get(100).getStatus().getCurrent().vmStatus();

System.out.println(result.isSuccessStatusCode()
        ? "VM " + result.getData().get("vmid").asInt() + " is " + result.getData().get("status").asText()
        : result.getStatusCode() + " " + result.getReasonPhrase());
```

What the token needs: [Permissions](https://corsinvest.github.io/cv4pve-api-java/permissions/).

The first two numbers of the version are the Proxmox VE version the client was generated from: 9.2.x is for Proxmox VE 9.2. Changes of each release: [CHANGELOG.md](https://github.com/Corsinvest/cv4pve-api-java/blob/master/CHANGELOG.md).

---

## Documentation

| | |
|---|---|
| [Getting started](https://corsinvest.github.io/cv4pve-api-java/getting-started/) | Install, connect, first calls |
| [Connection](https://corsinvest.github.io/cv4pve-api-java/connection/) | API token or password, two-factor authentication, certificates, timeout, proxy |
| [Permissions](https://corsinvest.github.io/cv4pve-api-java/permissions/) | The user, the token and the privileges an application needs |
| [Concepts](https://corsinvest.github.io/cv4pve-api-java/concepts/api-structure/) | API structure, results, indexed parameters, tasks, errors |
| [Examples](https://corsinvest.github.io/cv4pve-api-java/examples/common-tasks/) | Common tasks, creating a VM, bulk operations |
| [Troubleshooting](https://corsinvest.github.io/cv4pve-api-java/troubleshooting/) | Logging and the common errors |

---

## Related tools

Prefer a command line? [cv4pve-cli](https://github.com/Corsinvest/cv4pve-cli) calls the same API from any shell. The same client for .NET: [cv4pve-api-dotnet](https://github.com/Corsinvest/cv4pve-api-dotnet). From PowerShell: [cv4pve-api-powershell](https://github.com/Corsinvest/cv4pve-api-powershell). The whole suite: [corsinvest.it/cv4pve](https://www.corsinvest.it/en/cv4pve/).

---

## Support

Professional support and consulting available through [Corsinvest](https://www.corsinvest.it/en/cv4pve/).

---

Part of [cv4pve](https://www.corsinvest.it/cv4pve) suite | Made with ❤️ in Italy by [Corsinvest](https://www.corsinvest.it)

Copyright © Corsinvest Srl
