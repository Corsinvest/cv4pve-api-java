# cv4pve-api-java 🔧

<div align="center">

![cv4pve-api-java Banner](https://img.shields.io/badge/Corsinvest-Proxmox%20VE%20API%20Java-blue?style=for-the-badge&logo=java)

**🚀 Official Java Client Library Suite for Proxmox VE API**

[![License](https://img.shields.io/github/license/Corsinvest/cv4pve-api-java.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/Corsinvest/cv4pve-api-java.svg)](https://github.com/Corsinvest/cv4pve-api-java/releases)
![Maven Central](https://img.shields.io/maven-central/v/it.corsinvest.proxmoxve/cv4pve-api-java.svg)
[![Java Version](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://www.oracle.com/java/)

⭐ **We appreciate your star, it helps!** ⭐

```text
   ______                _                      __
  / ____/___  __________(_)___ _   _____  _____/ /_
 / /   / __ \/ ___/ ___/ / __ \ | / / _ \/ ___/ __/
/ /___/ /_/ / /  (__  ) / / / / |/ /  __(__  ) /_
\____/\____/_/  /____/_/_/ /_/|___/\___/____/\__/

Corsinvest for Proxmox VE Api Client  (Made in Italy 🇮🇹)
```

</div>

## 📖 About

**cv4pve-api-java** is a comprehensive Java client library that provides seamless integration with Proxmox VE's REST API. Designed for developers who need to programmatically manage virtual machines, containers, storage, and cluster resources in Proxmox VE environments.

## 📦 Package Suite

| Package | Description | Status |
|---------|-------------|---------|
| **cv4pve-api-java** | Core API Client Library | ✅ Available |

## 🚀 Quick Start

### Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>it.corsinvest.proxmoxve</groupId>
    <artifactId>cv4pve-api-java</artifactId>
    <version>9.0.0</version>
</dependency>
```

### Basic Usage

```java
import it.corsinvest.proxmoxve.api.PveClient;
import org.json.JSONArray;
import org.json.JSONObject;

PveClient client = new PveClient("your-proxmox-host.com", 8006);

if (client.login("root", "password", "pam")) {
    // Get cluster version
    System.out.println(client.getVersion().version().getResponse().get("data"));

    // List nodes
    JSONArray nodes = client.getNodes().index().getResponse().getJSONArray("data");
    for (int i = 0; i < nodes.length(); i++) {
        System.out.println(nodes.get(i));
    }

    // List VMs
    JSONArray vms = client.getNodes().get("pve1").getQemu().vmlist()
        .getResponse().getJSONArray("data");
    for (int i = 0; i < vms.length(); i++) {
        JSONObject vm = vms.getJSONObject(i);
        System.out.println("VM " + vm.getInt("vmid") + ": " +
            vm.getString("name") + " - Status: " + vm.getString("status"));
    }
}
```

## 🌟 Key Features

### Developer Experience

- **💡 Intuitive API Structure** - Mirrors Proxmox VE API hierarchy for easy navigation
- **📝 Comprehensive Documentation** - Detailed JavaDoc comments on all methods and parameters
- **🔧 Easy Integration** - Simple Maven dependency and minimal setup required
- **⚡ Flexible Response Handling** - Result class with comprehensive error handling

### Core Functionality

- **🌐 Complete API Coverage** - Full implementation of Proxmox VE REST API endpoints
- **🖥️ VM & Container Management** - Create, configure, start, stop, and monitor VMs and containers
- **💾 Storage Operations** - Manage storage pools, volumes, and backups
- **📊 Cluster Management** - Monitor cluster status, resources, and performance

### Enterprise Ready

- **🔐 Multiple Authentication Methods** - Username/password, API tokens, and two-factor authentication
- **🛡️ Security First** - Secure communication with SSL/TLS support
- **📈 Task Management** - Built-in support for monitoring long-running operations (waitForTaskToFinish, taskIsRunning)
- **⏱️ Connection Management** - Configurable timeouts and proxy support

### Technical Excellence

- **🚀 Minimal Dependencies** - Lightweight design using only org.json library
- **🏗️ Java 8+ Compatible** - Wide compatibility with modern and legacy environments
- **🔄 Error Handling** - Comprehensive Result class with status codes and error messages
- **📱 Cross-Platform** - Works on Windows, Linux, and macOS

## 📚 Result Class

The `Result` class provides comprehensive response handling:

```java
Result result = client.getNodes().index();

// Get response data
JSONObject response = result.getResponse();

// Check for errors
boolean hasError = result.responseInError();
String errorMessage = result.getError();

// HTTP status information
int statusCode = result.getStatusCode();
String reasonPhrase = result.getReasonPhrase();
boolean isSuccess = result.isSuccessStatusCode();
```

### Result Methods

- **getResponse()** - Returns JSONObject from Proxmox VE (data, errors, etc.)
- **responseInError()** - Boolean indicating errors from Proxmox VE
- **getStatusCode()** - HTTP response status code
- **getReasonPhrase()** - Status message from server
- **isSuccessStatusCode()** - Boolean indicating HTTP success (2xx status)
- **getError()** - Returns error message if present

## 📚 Advanced Features

### Tree Structure Navigation

Navigate the API using an intuitive tree structure that mirrors Proxmox VE's organization:

```java
client.getNodes().get("pve1").getQemu().get(100).getSnapshot().snapshotList();
```

### Task Management

Handle long-running operations efficiently:

```java
// Create snapshot
JSONObject result = client.getNodes().get("pve1")
    .getQemu().get(100).getSnapshot()
    .snapshot("my-snapshot")
    .getResponse();

String upid = result.getString("data");
System.out.println("Task UPID: " + upid);

// Wait for task completion
client.waitForTaskToFinish("pve1", upid, 500, 10000);

// Check task status
boolean isRunning = client.taskIsRunning("pve1", upid);
String exitStatus = client.getExitStatusTask("pve1", upid);
```

### API Token Authentication

From Proxmox VE 6.2+, use API tokens for authentication without passwords:

```java
// Format: USER@REALM!TOKENID=UUID
client.setApiToken("root@pam!mytoken=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
```

**Note:** When using Privilege Separation, ensure appropriate permissions are set for the API token.

### Lite Client Version

For basic operations, use `PveClientBase` with only get/set/create/delete methods:

```java
import it.corsinvest.proxmoxve.api.PveClientBase;

PveClientBase client = new PveClientBase("10.92.90.91", 8006);
// Use basic CRUD operations
```

### Debug Logging

Enable debug output to console for troubleshooting:

```java
client.setDebugLevel(2); // Set debug level (0-3)
```

## 🎯 Use Cases

Perfect for:
- **🏢 Infrastructure Automation** - Automate VM/CT deployment and configuration
- **📊 Monitoring & Analytics** - Build custom dashboards and monitoring solutions
- **💾 Backup Management** - Implement automated backup and disaster recovery workflows
- **🌐 Multi-tenant Environments** - Manage multiple Proxmox VE clusters and tenants
- **🔄 DevOps Integration** - Integrate with CI/CD pipelines and deployment automation

## 💡 Code Examples

### Snapshot Management

```java
// List snapshots
JSONArray snapshots = client.getNodes().get("pve1")
    .getQemu().get(100).getSnapshot().snapshotList()
    .getResponse().getJSONArray("data");

for (int i = 0; i < snapshots.length(); i++) {
    System.out.println(snapshots.get(i));
}

// Create snapshot
JSONObject createResult = client.getNodes().get("pve1")
    .getQemu().get(100).getSnapshot()
    .snapshot("backup-snapshot")
    .getResponse();

String upid = createResult.getString("data");
client.waitForTaskToFinish("pve1", upid, 500, 10000);

// Delete snapshot
Result deleteResult = client.getNodes().get("pve1")
    .getQemu().get(100).getSnapshot()
    .get("backup-snapshot").delsnapshot();

System.out.println(deleteResult.getResponse().get("data"));
```

### Iterating with Streams

```java
// Using forEach with JSONArray conversion
PveClient.<JSONObject>JSONArrayToList(
    client.getNodes().index().getResponse().getJSONArray("data")
).forEach((node) -> {
    System.out.println("Node: " + node.getString("node"));
});
```

## ⚙️ Requirements

- **Java:** 8 or higher
- **Dependencies:** org.json library (automatically managed by Maven)
- **Maven:** For dependency management

## 🤝 Community & Support

### 🆘 Getting Help

- 📚 **[Proxmox VE API Documentation](https://pve.proxmox.com/pve-docs/api-viewer/)** - Official API reference
- 🐛 **[GitHub Issues](https://github.com/Corsinvest/cv4pve-api-java/issues)** - Bug reports and feature requests
- 💼 **[Commercial Support](https://www.corsinvest.it/cv4pve)** - Professional consulting and support

### 🏢 About Corsinvest

**Corsinvest Srl** is an Italian software company specializing in virtualization solutions. We develop professional tools and libraries for Proxmox VE that help businesses automate and manage their virtual infrastructure efficiently.

### 🤝 Contributing

We welcome contributions from the community! Whether it's bug fixes, new features, or documentation improvements, your help makes this project better for everyone.

## 📄 License

**Copyright © Corsinvest Srl**

This software is part of the **cv4pve-tools** suite. For licensing details, please visit [LICENSE](LICENSE).

---

<div align="center">
  <sub>Part of <a href="https://www.corsinvest.it/cv4pve">cv4pve-tools</a> suite | Made with ❤️ in Italy by <a href="https://www.corsinvest.it">Corsinvest</a></sub>
</div>
