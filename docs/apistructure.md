# API Structure

This document explains the hierarchical structure of the Proxmox VE API and how to navigate it with cv4pve-api-java.

## Tree Navigation

The library follows Proxmox VE's hierarchical API structure. Each API endpoint is represented as a tree of Java objects.

```java
// Tree structure mirrors the API path
client.getNodes()                    // /api2/json/nodes
    .get("pve1")                     // /api2/json/nodes/pve1
    .getQemu()                       // /api2/json/nodes/pve1/qemu
    .get(100)                        // /api2/json/nodes/pve1/qemu/100
    .getSnapshot()                   // /api2/json/nodes/pve1/qemu/100/snapshot
    .snapshotList();                 // GET /api2/json/nodes/pve1/qemu/100/snapshot
```

## Main API Endpoints

### Cluster Operations

```java
// Get cluster status
client.getCluster().getStatus().getStatus();

// Get cluster resources
client.getCluster().getResources().resources();

// Access control
client.getAccess().getUsers().index();
```

### Node Operations

```java
// List all nodes
client.getNodes().index();

// Get node status
client.getNodes().get("pve1").getStatus().status();

// Node tasks
client.getNodes().get("pve1").getTasks().nodeTasks();
```

### VM Operations

```java
// List VMs on a node
client.getNodes().get("pve1").getQemu().vmlist();

// Get VM configuration
client.getNodes().get("pve1").getQemu().get(100).getConfig().vmConfig();

// VM status
client.getNodes().get("pve1").getQemu().get(100).getStatus().current();
```

### Container Operations

```java
// List containers
client.getNodes().get("pve1").getLxc().vmlist();

// Container configuration
client.getNodes().get("pve1").getLxc().get(100).getConfig().vmConfig();
```

### Storage Operations

```java
// List storage
client.getNodes().get("pve1").getStorage().index();

// Storage content
client.getNodes().get("pve1").getStorage().get("local").getContent().index();
```

## API Path Mapping

The Java method chain directly maps to the Proxmox VE API path:

| Java Code | API Path |
|-----------|----------|
| `client.getNodes()` | `/nodes` |
| `client.getNodes().get("pve1")` | `/nodes/pve1` |
| `client.getNodes().get("pve1").getQemu()` | `/nodes/pve1/qemu` |
| `client.getNodes().get("pve1").getQemu().get(100)` | `/nodes/pve1/qemu/100` |
| `client.getCluster().getStatus()` | `/cluster/status` |

## Resource Types

### Virtual Machines (Qemu)

```java
// Access VM by VMID
var vm = client.getNodes().get("pve1").getQemu().get(100);

// VM operations
vm.getStatus().start();    // Start VM
vm.getStatus().stop();     // Stop VM
vm.getStatus().shutdown(); // Shutdown VM
vm.getStatus().reset();    // Reset VM

// VM configuration
vm.getConfig().vmConfig(); // Get config
vm.getSnapshot();          // Manage snapshots
```

### Containers (LXC)

```java
// Access container by VMID
var ct = client.getNodes().get("pve1").getLxc().get(100);

// Container operations
ct.getStatus().start();
ct.getStatus().stop();
ct.getSnapshot();
```

### Storage

```java
// Access storage
var storage = client.getNodes().get("pve1").getStorage().get("local");

// Storage operations
storage.getContent().index();     // List content
storage.getStatus().read_status(); // Get status
```

## Navigation Patterns

### Listing Resources

```java
// List all nodes
Result nodes = client.getNodes().index();

// List all VMs on a node
Result vms = client.getNodes().get("pve1").getQemu().vmlist();

// List all storage on a node
Result storage = client.getNodes().get("pve1").getStorage().index();
```

### Accessing Specific Resources

```java
// Access specific VM
var vm = client.getNodes().get("pve1").getQemu().get(100);

// Access specific storage
var storage = client.getNodes().get("pve1").getStorage().get("local");

// Access specific network
var network = client.getNodes().get("pve1").getNetwork().get("vmbr0");
```

### Nested Resources

```java
// Access VM snapshots
var snapshots = client.getNodes().get("pve1")
    .getQemu().get(100)
    .getSnapshot();

// Create snapshot
snapshots.snapshot("backup-2024");

// Access specific snapshot
var snapshot = snapshots.get("backup-2024");
snapshot.delsnapshot(); // Delete snapshot
```

## Best Practices

1. **Use descriptive variable names** for clarity
2. **Chain methods logically** following the API structure
3. **Cache frequently accessed nodes** to avoid repeated lookups
4. **Check result status** after each operation
5. **Use constants** for node names and VMIDs when possible

## Example: Complete Workflow

```java
var client = new PveClient("pve.example.com", 8006);
client.login("root", "password", "pam");

// Navigate to specific VM
var nodeName = "pve1";
int vmid = 100;

// Get VM config
var config = client.getNodes()
    .get(nodeName)
    .getQemu()
    .get(vmid)
    .getConfig()
    .vmConfig()
    .getData();

System.out.println("VM Name: " + config.get("name").asText());

// Create snapshot
var upid = client.getNodes()
    .get(nodeName)
    .getQemu()
    .get(vmid)
    .getSnapshot()
    .snapshot("backup-now")
    .getData()
    .asText();

client.waitForTaskToFinish(nodeName, upid);
System.out.println("Snapshot created successfully");
```
