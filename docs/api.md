# Corsinvest.ProxmoxVE.Api for Java

```xml
<dependency>
    <groupId>it.corsinvest.proxmoxve</groupId>
    <artifactId>cv4pve-api-java</artifactId>
    <version>9.1.0</version>
</dependency>
```

## Key Features

- **Tree Structure** - Mirrors the Proxmox VE API hierarchy exactly
- **Modern Java 17+** - Uses var, pattern matching, and contemporary features
- **Auto-Generated** - Generated from official Proxmox VE API documentation
- **JavaDoc** - Complete code completion and documentation
- **Multiple Auth** - Username/password, API tokens, 2FA support
- **Flexible Results** - Responses with comprehensive metadata via Jackson
- **Enterprise Ready** - SSL validation, timeouts, proxy support

---

## API Structure

The library follows the exact structure of the [Proxmox VE API](https://pve.proxmox.com/pve-docs/api-viewer/):

```java
// API Path: /cluster/status
client.getCluster().getStatus().getStatus()

// API Path: /nodes/{node}/qemu/{vmid}/config
client.getNodes().get("pve1").getQemu().get(100).getConfig().vmConfig()

// API Path: /nodes/{node}/lxc/{vmid}/snapshot
client.getNodes().get("pve1").getLxc().get(101).getSnapshot().snapshot("snap-name")

// API Path: /nodes/{node}/storage/{storage}
client.getNodes().get("pve1").getStorage().get("local").status()
```

### HTTP Method Mapping

| HTTP Method | Java Method | Purpose | Example |
|-------------|-------------|---------|---------|
| `GET` | `resource.get()` | Retrieve information | `vm.getConfig().vmConfig()` |
| `POST` | `resource.create(parameters)` | Create resources | `vm.getSnapshot().snapshot("snap-name")` |
| `PUT` | `resource.set(parameters)` | Update resources | `vm.getConfig().updateVm(...)` |
| `DELETE` | `resource.delete()` | Remove resources | `vm.delete()` |

> **Note:** Some endpoints also have specific method names like `vmConfig()`, `snapshot()`, etc. that map to the appropriate HTTP verbs.

---

## Authentication

### Username/Password Authentication

```java
import it.corsinvest.proxmoxve.api.*;

var client = new PveClient("pve.example.com", 8006);

// Basic login
boolean success = client.login("root", "password");

// Login with realm
boolean success = client.login("admin@pve", "password");

// Two-factor authentication
boolean success = client.login("root", "password", "pam", "123456");
```

### API Token Authentication (Recommended)

```java
var client = new PveClient("pve.example.com", 8006);

// Set API token (Proxmox VE 6.2+)
client.setApiToken("user@realm!tokenid=uuid");

// No login() call needed with API tokens
var version = client.getVersion().version();
```

### Advanced Configuration

```java
// Basic configuration
var client = new PveClient("pve.example.com", 8006);

// Custom timeout (default: 120 seconds)
client.setTimeout(300000); // 5 minutes in milliseconds

// Validate SSL certificates (default: false)
client.setValidateCertificate(true);

// Custom hostname verifier
client.setHostnameVerifier((hostname, session) -> {
    // Custom hostname validation logic
    return validateCustomHostname(hostname);
});

// Proxy configuration
var proxy = new Proxy(
    Proxy.Type.HTTP,
    new InetSocketAddress("proxy.company.com", 8080)
);
client.setProxy(proxy);
```

### Enterprise Configuration Scenarios

<details>
<summary><strong>Custom Certificate Validation</strong></summary>

```java
// Custom certificate validation for corporate environments
var client = new PveClient("pve.company.com", 8006);

// Custom trust manager for specific certificates
var trustManager = new X509TrustManager() {
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    public void checkClientTrusted(X509Certificate[] certs, String authType) {
        // Implementation for client cert validation
    }

    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        // Allow specific certificate thumbprints
        var allowedThumbprints = List.of(
            "A1:B2:C3:D4:E5:F6:...", // Production cert
            "F6:E5:D4:C3:B2:A1:..."  // Staging cert
        );

        for (X509Certificate cert : certs) {
            String thumbprint = getThumbprint(cert);
            if (allowedThumbprints.contains(thumbprint)) {
                return;
            }
        }
        throw new CertificateException("Certificate not in allowed list");
    }
};

client.setTrustManager(trustManager);
```

</details>

<details>
<summary><strong>Proxy Configuration</strong></summary>

```java
// Corporate proxy setup
var proxy = new Proxy(
    Proxy.Type.HTTP,
    new InetSocketAddress("proxy.company.com", 8080)
);

// Proxy authentication if required
Authenticator.setDefault(new Authenticator() {
    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
        if (getRequestorType() == RequestorType.PROXY) {
            return new PasswordAuthentication("proxyuser", "proxypass".toCharArray());
        }
        return null;
    }
});

var client = new PveClient("pve.company.com", 8006);
client.setProxy(proxy);
```

</details>

<details>
<summary><strong>Request/Response Logging</strong></summary>

```java
// Custom logging for debugging
var client = new PveClient("pve.example.com", 8006);

// Enable debug logging (0-3)
// 0 = No debug
// 1 = Basic info
// 2 = Detailed info
// 3 = Full debug including response bodies
client.setDebugLevel(3);

// Or use java.util.logging
Logger logger = Logger.getLogger(PveClient.class.getName());
logger.setLevel(Level.FINE);

// Configure handler
ConsoleHandler handler = new ConsoleHandler();
handler.setLevel(Level.FINE);
logger.addHandler(handler);
```

</details>

<details>
<summary><strong>Retry Policies</strong></summary>

```java
// Retry logic for resilient API calls
public Result retryOperation(Supplier<Result> operation, int maxRetries) {
    int retries = 0;
    while (retries < maxRetries) {
        var result = operation.get();
        if (result.isSuccessStatusCode()) {
            return result;
        }

        retries++;
        if (retries < maxRetries) {
            try {
                Thread.sleep(1000 * (long)Math.pow(2, retries)); // Exponential backoff
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    return null;
}

// Usage
var result = retryOperation(
    () -> client.getNodes().get("pve1").getStatus().status(),
    3
);
```

</details>

---

## Working with Results

Every API call returns a `Result` object containing comprehensive response information:

```java
var result = client.getNodes().get("pve1").getQemu().get(100).getConfig().vmConfig();

// Check success
if (result.isSuccessStatusCode()) {
    // Access response data (JsonNode)
    var data = result.getData();
    System.out.println("VM Name: " + data.get("name").asText());
    System.out.println("Memory: " + data.get("memory").asInt());
    System.out.println("Cores: " + data.get("cores").asInt());
} else {
    // Handle errors
    System.out.println("Error: " + result.getError());
    System.out.println("Status: " + result.getStatusCode() + " - " + result.getReasonPhrase());
}
```

### Result Properties

```java
public class Result {
    // Response data from Proxmox VE (JsonNode)
    public JsonNode getResponse();

    // Convenience method to get data directly
    public JsonNode getData();

    // HTTP response information
    public int getStatusCode();
    public String getReasonPhrase();
    public boolean isSuccessStatusCode();

    // Utility methods
    public boolean responseInError();
    public String getError();
}
```

---

## Basic Examples

### Virtual Machine Management

<details>
<summary><strong>VM Configuration</strong></summary>

```java
import it.corsinvest.proxmoxve.api.*;

var client = new PveClient("pve.example.com", 8006);
client.login("admin@pve", "password");

// Get VM configuration
var vm = client.getNodes().get("pve1").getQemu().get(100);
var vmData = vm.getConfig().vmConfig().getData();

System.out.println("VM Name: " + vmData.get("name").asText());
System.out.println("Memory: " + vmData.get("memory").asInt() + " MB");
System.out.println("CPUs: " + vmData.get("cores").asInt());
System.out.println("OS Type: " + vmData.get("ostype").asText());

// Update VM configuration
var params = Map.of(
    "memory", 8192,  // 8GB RAM
    "cores", 4       // 4 CPU cores
);
vm.getConfig().updateVm(params);
System.out.println("VM configuration updated!");
```

</details>

<details>
<summary><strong>Snapshot Management</strong></summary>

```java
// Create snapshot
client.getNodes().get("pve1").getQemu().get(100)
    .getSnapshot().snapshot("backup-before-update", "Pre-update backup");
System.out.println("Snapshot created successfully!");

// List snapshots
var snapshots = client.getNodes().get("pve1").getQemu().get(100)
    .getSnapshot().snapshotList().getData();

System.out.println("Available snapshots:");
for (JsonNode snap : snapshots) {
    System.out.println("  - " + snap.get("name").asText() + ": " +
                     snap.get("description").asText() + " (" +
                     snap.get("snaptime").asText() + ")");
}

// Delete snapshot
client.getNodes().get("pve1").getQemu().get(100)
    .getSnapshot().get("backup-before-update").delsnapshot();
System.out.println("Snapshot deleted successfully!");
```

</details>

<details>
<summary><strong>VM Status Management</strong></summary>

```java
var vm = client.getNodes().get("pve1").getQemu().get(100);

// Get current status
var statusData = vm.getStatus().current().getData();
System.out.println("Current status: " + statusData.get("status").asText());
System.out.println("CPU usage: " + String.format("%.2f%%", statusData.get("cpu").asDouble() * 100));
System.out.println("Memory usage: " + String.format("%.2f%%",
    (statusData.get("mem").asDouble() / statusData.get("maxmem").asDouble()) * 100));

// Start VM
if ("stopped".equals(statusData.get("status").asText())) {
    vm.getStatus().start();
    System.out.println("VM started successfully!");
}

// Stop VM
vm.getStatus().stop();
System.out.println("VM stopped successfully!");

// Restart VM
vm.getStatus().reboot();
System.out.println("VM restarted successfully!");
```

</details>

### Container Management

<details>
<summary><strong>LXC Container Operations</strong></summary>

```java
// Access LXC container
var container = client.getNodes().get("pve1").getLxc().get(101);

// Get container configuration
var ctData = container.getConfig().vmConfig().getData();
System.out.println("Container: " + ctData.get("hostname").asText());
System.out.println("OS Template: " + ctData.get("ostemplate").asText());
System.out.println("Memory: " + ctData.get("memory").asInt() + " MB");

// Container status operations
var status = container.getStatus().current().getData();
System.out.println("Status: " + status.get("status").asText());

// Start container
if ("stopped".equals(status.get("status").asText())) {
    container.getStatus().start();
    System.out.println("Container started!");
}

// Create container snapshot
container.getSnapshot().snapshot("backup-snapshot");
System.out.println("Container snapshot created!");
```

</details>

### Cluster Operations

<details>
<summary><strong>Cluster Status and Resources</strong></summary>

```java
// Get cluster status
var clusterStatus = client.getCluster().getStatus().getStatus().getData();
System.out.println("Cluster Status:");
for (JsonNode item : clusterStatus) {
    System.out.println("  " + item.get("type").asText() + ": " +
                     item.get("name").asText() + " - " +
                     item.get("status").asText());
}

// Get cluster resources
var resources = client.getCluster().getResources().resources().getData();
System.out.println("Cluster Resources:");
for (JsonNode resource : resources) {
    if ("node".equals(resource.get("type").asText())) {
        System.out.printf("  Node: %s - CPU: %.2f%%, Memory: %.2f%%%n",
            resource.get("node").asText(),
            resource.get("cpu").asDouble() * 100,
            (resource.get("mem").asDouble() / resource.get("maxmem").asDouble()) * 100);
    } else if ("qemu".equals(resource.get("type").asText())) {
        System.out.printf("  VM: %d (%s) on %s - %s%n",
            resource.get("vmid").asInt(),
            resource.get("name").asText(),
            resource.get("node").asText(),
            resource.get("status").asText());
    }
}

// Get node information
var nodes = client.getNodes().index().getData();
System.out.println("Available Nodes:");
for (JsonNode node : nodes) {
    System.out.println("  " + node.get("node").asText() + ": " +
                     node.get("status").asText() + " - Uptime: " +
                     node.get("uptime").asInt() + "s");
}
```

</details>

### Storage Management

<details>
<summary><strong>Storage Operations</strong></summary>

```java
// List storage on a node
var storages = client.getNodes().get("pve1").getStorage().index().getData();
System.out.println("Available Storage:");
for (JsonNode storage : storages) {
    System.out.printf("  %s: %s - %.2f GB available%n",
        storage.get("storage").asText(),
        storage.get("type").asText(),
        storage.get("avail").asLong() / (1024.0 * 1024.0 * 1024.0));
}

// Get specific storage details
var storageData = client.getNodes().get("pve1").getStorage().get("local").status().getData();
System.out.println("Storage: " + storageData.get("storage").asText());
System.out.println("Type: " + storageData.get("type").asText());
System.out.printf("Total: %.2f GB%n", storageData.get("total").asLong() / (1024.0 * 1024.0 * 1024.0));
System.out.printf("Used: %.2f GB%n", storageData.get("used").asLong() / (1024.0 * 1024.0 * 1024.0));
System.out.printf("Available: %.2f GB%n", storageData.get("avail").asLong() / (1024.0 * 1024.0 * 1024.0));

// List storage content
var content = client.getNodes().get("pve1").getStorage().get("local").getContent().index().getData();
System.out.println("Storage Content:");
for (JsonNode item : content) {
    System.out.printf("  %s: %s - %.2f MB%n",
        item.get("volid").asText(),
        item.get("format").asText(),
        item.get("size").asLong() / (1024.0 * 1024.0));
}
```

</details>

---

## Advanced Features

### Task Management

```java
// Long-running operations return task IDs
var createResult = client.getNodes().get("pve1").getQemu().createVm(
    Map.of(
        "vmid", 999,
        "name", "test-vm",
        "memory", 2048
    )
);

if (createResult.isSuccessStatusCode()) {
    String taskId = createResult.getData().asText();
    System.out.println("Task started: " + taskId);

    // Monitor task progress
    while (true) {
        var taskStatus = client.getNodes().get("pve1")
            .getTasks().get(taskId).getStatus().readTaskStatus();

        if (taskStatus.isSuccessStatusCode()) {
            var status = taskStatus.getData().get("status").asText();

            if ("stopped".equals(status)) {
                var exitStatus = taskStatus.getData().get("exitstatus").asText();
                System.out.println("Task completed with status: " + exitStatus);
                break;
            } else if ("running".equals(status)) {
                System.out.println("Task still running...");
                Thread.sleep(2000);
            }
        }
    }
}
```

### SSL and Security

```java
var client = new PveClient("pve.example.com", 8006);

// Enable SSL certificate validation
client.setValidateCertificate(true);

// Set custom timeout
client.setTimeout(600000); // 10 minutes

// Use API token for secure authentication
client.setApiToken("automation@pve!secure-token=uuid-here");

// API calls now use validated SSL and secure token
var result = client.getVersion().version();
```

---

## Best Practices

### Recommended Patterns

```java
// 1. Always check isSuccessStatusCode()
var result = client.getCluster().getStatus().getStatus();
if (result.isSuccessStatusCode()) {
    // Process successful response
    processClusterStatus(result.getData());
} else {
    // Handle error appropriately
    logger.error("API call failed: " + result.getError());
}

// 2. Use API tokens for automation
var client = new PveClient("pve.cluster.com", 8006);
client.setApiToken(System.getenv("PROXMOX_API_TOKEN"));

// 3. Configure timeouts for long operations
client.setTimeout(900000); // 15 minutes

// 4. Enable SSL validation in production
client.setValidateCertificate(true);

// 5. Use proxy for enterprise scenarios
var proxy = new Proxy(Proxy.Type.HTTP,
    new InetSocketAddress("proxy.company.com", 8080));
client.setProxy(proxy);

// 6. Enable logging for debugging
client.setDebugLevel(2);
```

### Common Pitfalls to Avoid

```java
// Don't ignore error handling
var result = client.getNodes().get("pve1").getQemu().get(100).getStatus().start();
// Missing: if (!result.isSuccessStatusCode()) { ... }

// Don't hardcode credentials
client.login("root", "password123"); // Bad
// Better: Use environment variables or secure storage

// Don't assume JsonNode properties exist
System.out.println(result.getData().get("nonexistent").asText()); // May throw
// Better: Check if property exists
if (result.getData().has("property")) {
    System.out.println(result.getData().get("property").asText());
}
```
