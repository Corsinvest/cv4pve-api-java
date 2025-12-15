# Corsinvest.ProxmoxVE.Api for Java

```
   ______                _                      __
  / ____/___  __________(_)___ _   _____  _____/ /_
 / /   / __ \/ ___/ ___/ / __ \ | / / _ \/ ___/ __/
/ /___/ /_/ / /  (__  ) / / / / |/ /  __(__  ) /_
\____/\____/_/  /____/_/_/ /_/|___/\___/____/\__/

Proxmox VE API Client for Java (Made in Italy)
```

[![License](https://img.shields.io/github/license/Corsinvest/cv4pve-api-java.svg?style=flat-square)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-blue?style=flat-square&logo=java)](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)
[![Maven Central](https://img.shields.io/maven-metadata/v.svg?metadataUrl=https%3A%2F%2Frepo1.maven.org%2Fmaven2%2Fit%2Fcorsinvest%2Fproxmoxve%2Fcv4pve-api-java%2Fmaven-metadata.xml&label=maven-central&style=flat-square)](https://central.sonatype.com/artifact/it.corsinvest.proxmoxve/cv4pve-api-java)


---

## Quick Start

### Add the dependency to your project

**Maven**

```xml
<dependency>
    <groupId>it.corsinvest.proxmoxve</groupId>
    <artifactId>cv4pve-api-java</artifactId>
    <version>9.1.1</version>
</dependency>
```

**Gradle**

```gradle
implementation 'it.corsinvest.proxmoxve:cv4pve-api-java:9.1.1'
```

### Basic Usage

```java
import it.corsinvest.proxmoxve.*;

// Create client and authenticate
var client = new PveClient("your-proxmox-host.com", 8006);
if (client.login("root@pam", "your-password")) {
    // Get cluster status
    var status = client.getCluster().getStatus().getStatus().getData();
    System.out.println("Cluster: " + status.get(0).get("name").asText());

    // Manage VMs
    var vm = client.getNodes().get("pve1")
        .getQemu().get(100).getConfig().vmConfig()
        .getData();
    System.out.println("VM: " + vm.get("name").asText());
}
```

---

## Key Features

### Developer Experience
- **Intuitive API structure** that mirrors Proxmox VE API hierarchy
- **Modern Java 17+** with var, pattern matching, records, and other contemporary features
- **Jackson JSON parsing** for robust data handling
- **JavaDoc support** in all IDEs
- **Auto-generated** from official API documentation
- **Tree structure** matching Proxmox VE API paths

### Core Functionality
- **Full API coverage** for Proxmox VE 9.x
- **VM/CT management** (create, configure, snapshot, clone)
- **Cluster operations** (status, resources, HA, corosync)
- **Storage management** (local, shared, backup, replication)
- **Network configuration** (bridges, VLANs, SDN, firewall)

### Enterprise Ready
- **API token authentication** (Proxmox VE 6.2+)
- **Two-factor authentication** support
- **SSL certificate validation** with custom trust managers
- **Configurable timeouts** and HTTP proxy support
- **Thread-safe connection handling**

---

## Documentation

### Getting Started

- **[Authentication](./docs/authentication.md)** - API tokens and security
- **[Basic Examples](./docs/examples.md)** - Common usage patterns
- **[Advanced Usage](./docs/advanced.md)** - Complex scenarios and best practices
- **[Common Issues](./docs/common-issues.md)** - Configuration patterns and troubleshooting

### API Reference

- **[API Structure](./docs/apistructure.md)** - Understanding the tree structure
- **[Result Handling](./docs/results.md)** - Working with responses
- **[Error Handling](./docs/errorhandling.md)** - Exception management
- **[Task Management](./docs/tasks.md)** - Long-running operations

---

## Examples

### VM Management

```java
// Create and configure a VM
var client = new PveClient("pve.example.com", 8006);
client.login("admin@pve", "password");

var result = client.getNodes().get("pve1").getQemu().createVm(
    100,           // vmid
    "web-server",  // name
    4096,          // memory
    2              // cores
);

if (result.isSuccessStatusCode()) {
    System.out.println("VM created successfully!");
}
```

### Cluster Monitoring

```java
// Get cluster resources
var resources = client.getCluster().getResources().resources().getData();

for (var resource : resources) {
    if (resource.get("type").asText().equals("qemu")) {
        System.out.println("VM " + resource.get("vmid").asInt() + ": " +
                          resource.get("name").asText() + " on " +
                          resource.get("node").asText() + " - " +
                          resource.get("status").asText());
    }
}
```

### VM Discovery

```java
// Get all VMs in cluster
var resources = client.getCluster().getResources().resources().getData();

for (var resource : resources) {
    if (resource.get("type").asText().equals("qemu")) {
        var node = resource.get("node").asText();
        var vmid = resource.get("vmid").asInt();
        var name = resource.get("name").asText();
        var status = resource.get("status").asText();
        System.out.println("VM " + vmid + " (" + name + ") on " + node + " - " + status);
    }
}
```

---

## Support

Professional support and consulting available through [Corsinvest](https://www.corsinvest.it/cv4pve).

---

Part of [cv4pve](https://www.corsinvest.it/cv4pve) suite | Made with ❤️ in Italy by [Corsinvest](https://www.corsinvest.it)

Copyright © Corsinvest Srl