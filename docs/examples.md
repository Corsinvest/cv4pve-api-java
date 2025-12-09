# Basic Examples

This guide provides common usage patterns and practical examples for getting started with the Proxmox VE API.

## Getting Started

### **Basic Connection**

```java
import it.corsinvest.proxmoxve.api.*;

// Create client and authenticate
var client = new PveClient("pve.example.com", 8006);
client.setApiToken("user@pve!token=uuid");

// Test connection
var version = client.getVersion().version();
if (version.isSuccessStatusCode()) {
    System.out.println("Connected to Proxmox VE " +
        version.getResponse().get("data").get("version").asText());
}
```

### **Client Setup with Error Handling**

```java
public static PveClient createClient() {
    var client = new PveClient("pve.local", 8006);
    client.setValidateCertificate(false); // For development
    client.setTimeout(120000); // 2 minutes

    try {
        // Use API token or login
        String token = System.getenv("PVE_TOKEN");
        if (token != null && !token.isEmpty()) {
            client.setApiToken(token);
        } else {
            boolean success = client.login("root@pam", "password");
            if (!success) {
                throw new Exception("Authentication failed");
            }
        }

        return client;
    } catch (Exception ex) {
        System.out.println("Failed to create client: " + ex.getMessage());
        throw new RuntimeException(ex);
    }
}
```

---

## Virtual Machine Operations

### **List Virtual Machines**

```java
// Get all VMs in cluster
var resources = client.getCluster().getResources().resources().getData();

for (JsonNode resource : resources) {
    if ("qemu".equals(resource.get("type").asText())) {
        System.out.printf("VM %d: %s on %s - %s%n",
            resource.get("vmid").asInt(),
            resource.get("name").asText(),
            resource.get("node").asText(),
            resource.get("status").asText());
    }
}

// Filter running VMs
var runningVms = new ArrayList<JsonNode>();
for (JsonNode resource : resources) {
    if ("qemu".equals(resource.get("type").asText()) &&
        "running".equals(resource.get("status").asText())) {
        runningVms.add(resource);
    }
}
System.out.println("Running VMs: " + runningVms.size());
```

### **Get VM Configuration**

```java
// Get VM configuration
var config = client.getNodes().get("pve1").getQemu().get(100)
    .getConfig().vmConfig().getData();

System.out.println("VM Name: " + config.get("name").asText());
System.out.println("Memory: " + config.get("memory").asInt() + " MB");
System.out.println("CPU Cores: " + config.get("cores").asInt());
System.out.println("Boot Order: " + config.get("boot").asText());
```

### **VM Power Management**

```java
var vm = client.getNodes().get("pve1").getQemu().get(100);

// Start VM
vm.getStatus().start();
System.out.println("VM started successfully");

// Stop VM
vm.getStatus().stop();
System.out.println("VM stopped successfully");

// Restart VM
vm.getStatus().reboot();
System.out.println("VM restarted successfully");

// Get current status
var data = vm.getStatus().current().getData();
System.out.println("VM Status: " + data.get("status").asText());
System.out.printf("CPU Usage: %.2f%%%n", data.get("cpu").asDouble() * 100);
System.out.printf("Memory: %.2f%%%n",
    (data.get("mem").asDouble() / data.get("maxmem").asDouble()) * 100);
```

### **Snapshot Management**

```java
var vm = client.getNodes().get("pve1").getQemu().get(100);

// Create snapshot
vm.getSnapshot().snapshot("backup-2024", "Pre-update backup");
System.out.println("Snapshot created successfully");

// List snapshots
var snapshots = vm.getSnapshot().snapshotList().getData();
System.out.println("Available snapshots:");
for (JsonNode snapshot : snapshots) {
    System.out.printf("  - %s: %s (%s)%n",
        snapshot.get("name").asText(),
        snapshot.get("description").asText(),
        snapshot.get("snaptime").asText());
}

// Restore snapshot
vm.getSnapshot().get("backup-2024").rollback();
System.out.println("Snapshot restored successfully");

// Delete snapshot
vm.getSnapshot().get("backup-2024").delsnapshot();
System.out.println("Snapshot deleted successfully");
```

---

## Container Operations

### **List Containers**

```java
// Get all containers
var resources = client.getCluster().getResources().resources().getData();

for (JsonNode resource : resources) {
    if ("lxc".equals(resource.get("type").asText())) {
        System.out.printf("CT %d: %s on %s - %s%n",
            resource.get("vmid").asInt(),
            resource.get("name").asText(),
            resource.get("node").asText(),
            resource.get("status").asText());
    }
}
```

### **Container Management**

```java
var container = client.getNodes().get("pve1").getLxc().get(101);

// Get container configuration
var ctConfig = container.getConfig().vmConfig().getData();
System.out.println("Container: " + ctConfig.get("hostname").asText());
System.out.println("OS Template: " + ctConfig.get("ostemplate").asText());
System.out.println("Memory: " + ctConfig.get("memory").asInt() + " MB");

// Start container
container.getStatus().start();
System.out.println("Container started");

// Get container status
var data = container.getStatus().current().getData();
System.out.println("Status: " + data.get("status").asText());
System.out.println("Uptime: " + data.get("uptime").asInt() + " seconds");
```

---

## Cluster Operations

### **Cluster Status**

```java
// Get cluster status
var status = client.getCluster().getStatus().getStatus().getData();
System.out.println("Cluster Status:");
for (JsonNode item : status) {
    System.out.printf("  %s: %s - %s%n",
        item.get("type").asText(),
        item.get("name").asText(),
        item.get("status").asText());
}
```

### **Node Information**

```java
// Get all nodes
var nodes = client.getNodes().index().getData();
System.out.println("Available Nodes:");
for (JsonNode node : nodes) {
    System.out.println("  " + node.get("node").asText() + ": " +
                     node.get("status").asText());
    System.out.printf("    CPU: %.2f%%%n", node.get("cpu").asDouble() * 100);
    System.out.printf("    Memory: %.2f%%%n",
        (node.get("mem").asDouble() / node.get("maxmem").asDouble()) * 100);
    System.out.println("    Uptime: " +
        java.time.Duration.ofSeconds(node.get("uptime").asInt()));
}
```

### **Storage Information**

```java
// Get storage for a specific node
var storages = client.getNodes().get("pve1").getStorage().index().getData();
System.out.println("Available Storage:");
for (JsonNode storage : storages) {
    double usedPercent = (storage.get("used").asDouble() /
                        storage.get("total").asDouble()) * 100;
    System.out.printf("  %s (%s): %.1f%% used%n",
        storage.get("storage").asText(),
        storage.get("type").asText(),
        usedPercent);
    System.out.printf("    Total: %.2f GB%n",
        storage.get("total").asLong() / (1024.0 * 1024 * 1024));
    System.out.printf("    Available: %.2f GB%n",
        storage.get("avail").asLong() / (1024.0 * 1024 * 1024));
}
```

---

## Common Patterns

### **Resource Monitoring**

```java
public static void monitorResources(PveClient client) throws InterruptedException {
    while (true) {
        var resources = client.getCluster().getResources().resources().getData();

        System.out.print("\033[H\033[2J"); // Clear console
        System.out.flush();
        System.out.println("Proxmox VE Resource Monitor - " +
            java.time.LocalTime.now());
        System.out.println("=".repeat(50));

        // Count by type
        int nodeCount = 0, vmCount = 0, ctCount = 0;
        int runningVms = 0, runningCts = 0;

        for (JsonNode resource : resources) {
            String type = resource.get("type").asText();
            String status = resource.get("status").asText();

            switch (type) {
                case "node":
                    nodeCount++;
                    System.out.printf("  %s: CPU %.1f%%, Memory %.1f%%%n",
                        resource.get("node").asText(),
                        resource.get("cpu").asDouble() * 100,
                        (resource.get("mem").asDouble() /
                         resource.get("maxmem").asDouble()) * 100);
                    break;
                case "qemu":
                    vmCount++;
                    if ("running".equals(status)) runningVms++;
                    break;
                case "lxc":
                    ctCount++;
                    if ("running".equals(status)) runningCts++;
                    break;
            }
        }

        System.out.printf("\nNodes: %d%n", nodeCount);
        System.out.printf("VMs: %d (%d running)%n", vmCount, runningVms);
        System.out.printf("Containers: %d (%d running)%n", ctCount, runningCts);

        Thread.sleep(5000); // Update every 5 seconds
    }
}
```

### **Batch Operations**

```java
public static void batchVmOperation(PveClient client, int[] vmIds, String operation) {
    var resources = client.getCluster().getResources().resources().getData();

    for (int vmId : vmIds) {
        // Find VM location
        JsonNode vmResource = null;
        for (JsonNode resource : resources) {
            if ("qemu".equals(resource.get("type").asText()) &&
                resource.get("vmid").asInt() == vmId) {
                vmResource = resource;
                break;
            }
        }

        if (vmResource != null) {
            String node = vmResource.get("node").asText();
            var vm = client.getNodes().get(node).getQemu().get(vmId);

            Result result = switch (operation.toLowerCase()) {
                case "start" -> vm.getStatus().start();
                case "stop" -> vm.getStatus().stop();
                case "restart" -> vm.getStatus().reboot();
                default -> throw new IllegalArgumentException("Unknown operation: " + operation);
            };

            boolean success = result.isSuccessStatusCode();
            System.out.printf("VM %d %s: %s%n",
                vmId, operation, success ? "Success" : "Failed");
        }
    }
}
```

### **Performance Monitoring**

```java
public static void getVmPerformance(PveClient client, String node, int vmId) {
    var data = client.getNodes().get(node).getQemu().get(vmId)
        .getStatus().current().getData();

    System.out.println("VM " + vmId + " Performance:");
    System.out.println("  Status: " + data.get("status").asText());
    System.out.printf("  CPU Usage: %.2f%%%n", data.get("cpu").asDouble() * 100);
    System.out.printf("  Memory: %.2f GB / %.2f GB (%.1f%%)%n",
        data.get("mem").asLong() / (1024.0 * 1024 * 1024),
        data.get("maxmem").asLong() / (1024.0 * 1024 * 1024),
        (data.get("mem").asDouble() / data.get("maxmem").asDouble()) * 100);
    System.out.printf("  Disk Read: %.2f MB%n",
        data.get("diskread").asLong() / (1024.0 * 1024));
    System.out.printf("  Disk Write: %.2f MB%n",
        data.get("diskwrite").asLong() / (1024.0 * 1024));
    System.out.printf("  Network In: %.2f MB%n",
        data.get("netin").asLong() / (1024.0 * 1024));
    System.out.printf("  Network Out: %.2f MB%n",
        data.get("netout").asLong() / (1024.0 * 1024));
    System.out.println("  Uptime: " +
        java.time.Duration.ofSeconds(data.get("uptime").asInt()));
}
```

---

## Best Practices

### **Error Handling**

```java
public static boolean safeVmOperation(PveClient client, String node, int vmId, String operation) {
    try {
        var vm = client.getNodes().get(node).getQemu().get(vmId);

        Result result = switch (operation.toLowerCase()) {
            case "start" -> vm.getStatus().start();
            case "stop" -> vm.getStatus().stop();
            default -> throw new IllegalArgumentException("Unknown operation: " + operation);
        };

        if (result.isSuccessStatusCode()) {
            System.out.println("VM " + vmId + " " + operation + " successful");
            return true;
        } else {
            System.out.println("VM " + vmId + " " + operation + " failed: " +
                result.getError());
            return false;
        }
    } catch (Exception ex) {
        System.out.println("Exception during " + operation + " on VM " + vmId + ": " +
            ex.getMessage());
        return false;
    }
}
```

### **Resource Discovery**

```java
public static class VmLocation {
    public String node;
    public int vmId;

    public VmLocation(String node, int vmId) {
        this.node = node;
        this.vmId = vmId;
    }
}

public static VmLocation findVm(PveClient client, String vmName) {
    var resources = client.getCluster().getResources().resources().getData();

    for (JsonNode resource : resources) {
        if ("qemu".equals(resource.get("type").asText()) &&
            vmName.equalsIgnoreCase(resource.get("name").asText())) {
            return new VmLocation(
                resource.get("node").asText(),
                resource.get("vmid").asInt()
            );
        }
    }

    return null;
}

// Usage
var vmLocation = findVm(client, "web-server");
if (vmLocation != null) {
    var vm = client.getNodes().get(vmLocation.node).getQemu().get(vmLocation.vmId);
    // ... work with VM
}
```
