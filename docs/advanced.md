# Advanced Usage

This document covers advanced features and best practices.

## Debug Logging

Enable debug output to troubleshoot issues:

```java
var client = new PveClient("pve.example.com", 8006);

// Set debug level (0-3)
// 0 = No debug
// 1 = Basic info
// 2 = Detailed info
// 3 = Full debug including response bodies
client.setDebugLevel(2);

client.login("root", "password", "pam");
```

## Using PveClientBase (Lite Client)

For basic operations without the full API tree:

```java
import it.corsinvest.proxmoxve.api.PveClientBase;

var client = new PveClientBase("pve.example.com", 8006);
client.login("root", "password", "pam");

// Make raw API calls
var result = client.get("/nodes");
result = client.create("/nodes/pve1/qemu/100/status/start", null);
result = client.set("/nodes/pve1/qemu/100/config",
    new HashMap<String, Object>() {{
        put("memory", 2048);
    }});
result = client.delete("/nodes/pve1/qemu/100");
```

## Stream Processing

Use Java 8+ streams for efficient data processing:

```java
var nodes = client.getNodes().index().getData();

// Filter online nodes
for (JsonNode node : nodes) {
    if ("online".equals(node.get("status").asText())) {
        System.out.println("Online node: " + node.get("node").asText());
    }
}

// Find specific VM
for (JsonNode vm : vms) {
    if ("web-server".equals(vm.get("name").asText())) {
        // Found the VM
        break; // or process the vm
    }
}
```

## Batch Operations

Process multiple resources efficiently:

```java
// Get all VMs across all nodes
var allVMs = new ArrayList<JsonNode>();

var nodesResult = client.getNodes().index();
var nodes = nodesResult.getData();

for (JsonNode node : nodes) {
    String nodeName = node.get("node").asText();

    var vmsResult = client.getNodes().get(nodeName).getQemu().vmlist();
    var vms = vmsResult.getData();

    for (JsonNode vm : vms) {
        allVMs.add(vm);
    }
}

// Process all VMs
allVMs.forEach(vm -> {
    System.out.println("VM: " + vm.get("name").asText());
});
```

## Custom Timeout Handling

For long-running operations:

```java
// Increase timeout for task completion
// waitForTaskToFinish(node, upid, wait_interval_ms, timeout_ms)
client.waitForTaskToFinish("pve1", upid, 1000, 300000); // 5 minutes
```

## Error Recovery

Implement retry logic for transient failures:

```java
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
                Thread.sleep(1000 * retries); // Exponential backoff
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

## Working with Large Datasets

Process data incrementally to avoid memory issues:

```java
var result = client.getNodes().get("pve1").getQemu().vmlist();
var vms = result.getData();

// Process one at a time
for (JsonNode vm : vms) {
    processVM(vm); // Process and release
    // VM can be garbage collected after processing
}
```

## Secure Configuration

Best practices for production deployments:

```java
// Read credentials from environment
var host = System.getenv("PVE_HOST");
var apiToken = System.getenv("PVE_API_TOKEN");

if (host == null || apiToken == null) {
    throw new IllegalStateException("Missing required environment variables");
}

var client = new PveClient(host, 8006);
client.setApiToken(apiToken);

// Verify connection
var result = client.getVersion().version();
if (!result.isSuccessStatusCode()) {
    throw new RuntimeException("Failed to connect to Proxmox VE");
}
```

## Connection Management

```java
// Reuse client instance
public class ProxmoxManager {
    private final PveClient client;

    public ProxmoxManager(String host, String apiToken) {
        this.client = new PveClient(host, 8006);
        this.client.setApiToken(apiToken);
    }

    public List<JsonNode> getVMs(String node) {
        var result = client.getNodes().get(node).getQemu().vmlist();
        var vms = result.getData();
        var vmList = new ArrayList<JsonNode>();

        for (JsonNode vm : vms) {
            vmList.add(vm);
        }
        return vmList;
    }
}
```

## Best Practices

1. **Use API tokens** instead of passwords in production
2. **Implement proper error handling** at all levels
3. **Cache client instances** to avoid repeated authentication
4. **Use streams** for efficient data processing
5. **Enable debug logging** during development
6. **Set appropriate timeouts** for long operations
7. **Implement retry logic** for critical operations
8. **Process large datasets incrementally** to manage memory
9. **Store credentials securely** using environment variables
10. **Monitor and log** API operations

For more details, see [API Documentation](./api.md).
