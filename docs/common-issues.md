# Common Issues and Solutions

This guide covers common issues, configuration patterns, and solutions when working with the Proxmox VE API in Java.

---

## Indexed Parameters (Map)

Many VM/CT configuration methods use indexed parameters represented as `Map<Integer, String>` where the key is the index and the value is the configuration string.

### Understanding Indexed Parameters

Proxmox VE uses indexed parameters for devices that can have multiple instances. In the Java API, all indexed parameters are represented as `Map<Integer, String>` where the key is the device index (0, 1, 2...) and the value is the configuration string.

**Common Parameters:**
- **netN** - Network interfaces
- **scsiN** / **virtioN** / **sataN** / **ideN** - Disk devices
- **ipconfigN** - Cloud-init network configuration
- **hostpciN** / **usbN** - Hardware passthrough
- **mpN** - LXC mount points (containers only)

> **Note:** Proxmox VE supports many other indexed parameters. All use the same `Map<Integer, String>` pattern. For a complete list, refer to the [Proxmox VE API Documentation](https://pve.proxmox.com/pve-docs/api-viewer/).

### Basic Usage

```java
import it.corsinvest.proxmoxve.api.*;

var client = new PveClient("pve.example.com", 8006);
client.login("root@pam", "password");

// Configure network interfaces
var networks = Map.of(
    0, "model=virtio,bridge=vmbr0,firewall=1",
    1, "model=e1000,bridge=vmbr1"
);

// Configure disks
var disks = Map.of(
    0, "local-lvm:32,cache=writethrough",
    1, "local-lvm:64,iothread=1"
);

client.getNodes().get("pve1").getQemu().get(100).getConfig().updateVm(
    networks,  // netN
    disks      // scsiN
);
```

---

## Network Configuration (netN)

### Network Interface Syntax

Format: `model=<model>,bridge=<bridge>[,option=value,...]`

### Common Parameters

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| model | Network card model | virtio, e1000, rtl8139, vmxnet3 |
| bridge | Bridge to connect to | vmbr0, vmbr1 |
| firewall | Enable firewall | 0, 1 |
| link_down | Disconnect interface | 0, 1 |
| macaddr | MAC address | A2:B3:C4:D5:E6:F7 |
| mtu | MTU size | 1500, 9000 |
| queues | Number of queues | 1, 2, 4, 8 |
| rate | Rate limit (MB/s) | 10, 100 |
| tag | VLAN tag | 100, 200 |
| trunks | VLAN trunks | 10;20;30 |

### Examples

```java
// Basic VirtIO network
var networks = Map.of(
    0, "model=virtio,bridge=vmbr0"
);

// Network with VLAN and firewall
var networks = Map.of(
    0, "model=virtio,bridge=vmbr0,tag=100,firewall=1"
);

// Multiple networks with different settings
var networks = Map.of(
    0, "model=virtio,bridge=vmbr0,firewall=1",
    1, "model=e1000,bridge=vmbr1,rate=100",
    2, "model=virtio,bridge=vmbr0,tag=200,queues=4"
);
```

---

## Disk Configuration

### Disk Syntax

Format: `<storage>:<size>[,option=value,...]`

Or for existing volumes: `<storage>:<volume>[,option=value,...]`

### Storage Types

- **scsiN** - SCSI disks (0-30), most common, supports all features
- **virtioN** - VirtIO disks (0-15), high performance
- **sataN** - SATA disks (0-5), legacy compatibility
- **ideN** - IDE disks (0-3), legacy, often used for CD-ROM
- **efidisk0** - EFI disk for UEFI boot

### Common Disk Parameters

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| cache | Cache mode | none, writethrough, writeback, directsync, unsafe |
| discard | Enable TRIM/discard | on, ignore |
| iothread | Enable IO thread | 0, 1 |
| ssd | SSD emulation | 0, 1 |
| backup | Include in backup | 0, 1 |
| replicate | Enable replication | 0, 1 |
| media | Media type | disk, cdrom |
| size | Disk size | 32G, 100G, 1T |

### SCSI Disk Examples

```java
// Basic SCSI disk - 32GB
var disks = Map.of(
    0, "local-lvm:32"
);

// SCSI disk with options
var disks = Map.of(
    0, "local-lvm:32,cache=writethrough,iothread=1,discard=on"
);

// Multiple SCSI disks
var disks = Map.of(
    0, "local-lvm:32,cache=writethrough,iothread=1",  // OS disk
    1, "local-lvm:100,cache=none,iothread=1,discard=on",  // Data disk
    2, "local-lvm:200,backup=0"  // Temp disk, no backup
);
```

### VirtIO Disk Examples

```java
// VirtIO disks for maximum performance
var disks = Map.of(
    0, "local-lvm:32,cache=writethrough,discard=on",
    1, "ceph-storage:100,cache=none,iothread=1"
);
```

### SATA/IDE Examples

```java
// SATA disk
var sataDisks = Map.of(
    0, "local-lvm:32"
);

// IDE CD-ROM
var ideDisks = Map.of(
    2, "local:iso/ubuntu-22.04.iso,media=cdrom"
);
```

### EFI Disk

```java
// EFI disk for UEFI boot
String efidisk = "local-lvm:1,efitype=4m,pre-enrolled-keys=0";

client.getNodes().get("pve1").getQemu().get(100).getConfig().updateVm(
    "ovmf",      // bios
    efidisk      // efidisk0
);
```

---

## Cloud-Init Configuration (ipconfigN)

### IP Configuration Syntax

Format: `ip=<address>,gw=<gateway>[,option=value,...]`

### Examples

```java
// DHCP on all interfaces
var ipconfig = Map.of(
    0, "ip=dhcp"
);

// Static IP configuration
var ipconfig = Map.of(
    0, "ip=192.168.1.100/24,gw=192.168.1.1"
);

// Multiple interfaces with different configs
var ipconfig = Map.of(
    0, "ip=192.168.1.100/24,gw=192.168.1.1",  // Management
    1, "ip=10.0.0.100/24",  // Internal network
    2, "ip=dhcp"  // External network via DHCP
);

// IPv6 with auto-configuration
var ipconfig = Map.of(
    0, "ip=192.168.1.100/24,gw=192.168.1.1,ip6=auto"
);
```

---

## Complete Example

### Linux VM with VirtIO and Cloud-Init

```java
var client = new PveClient("pve.example.com", 8006);
client.login("admin@pve", "password");

// VM identifiers
int vmid = 101;
String vmName = "ubuntu-server";
String node = "pve1";

// Hardware resources
int memory = 4096;  // 4GB RAM
int cores = 2;
int sockets = 1;

// Configure VirtIO disks
var disks = Map.of(
    0, "local-lvm:32,cache=writethrough,discard=on"
);

// Configure network interfaces
var networks = Map.of(
    0, "model=virtio,bridge=vmbr0,firewall=1"
);

// Cloud-init IP configuration
var ipconfig = Map.of(
    0, "ip=192.168.1.100/24,gw=192.168.1.1"
);

// OS and boot settings
String ostype = "l26";
String scsihw = "virtio-scsi-single";
String boot = "order=virtio0";
String agent = "enabled=1";

// Cloud-init credentials and network
String ciuser = "admin";
String cipassword = "SecurePassword123!";
String sshkeys = "ssh-rsa AAAAB3NzaC1yc2E...";
String nameserver = "8.8.8.8 8.8.4.4";
String searchdomain = "example.com";

client.getNodes().get(node).getQemu().createVm(
    vmid,
    vmName,
    memory,
    cores,
    sockets,
    ostype,
    disks,         // virtioN
    networks,      // netN
    ipconfig,      // ipconfigN
    scsihw,
    boot,
    agent,
    ciuser,
    cipassword,
    sshkeys,
    nameserver,
    searchdomain
);

System.out.println("VM " + vmid + " created successfully with cloud-init!");
```

---

## Common Troubleshooting

### VM Won't Start

**Check configuration:**
```java
var config = client.getNodes().get("pve1").getQemu().get(100).getConfig().vmConfig().getData();
// Verify configuration is valid
System.out.println(config);
```

**Common issues:**
- Missing boot disk: Verify `boot` parameter points to valid disk
- Invalid network bridge: Check bridge exists on node
- Insufficient resources: Verify memory/CPU allocation

### Disk Not Found

Verify storage exists and has space:
```java
var storages = client.getNodes().get("pve1").getStorage().index();
for (var storage : storages.getData()) {
    System.out.println("Storage: " + storage.get("storage").asText());
    System.out.println("  Type: " + storage.get("type").asText());
    System.out.println("  Available: " + storage.get("avail").asText());
}
```

### Network Issues

Verify bridge configuration:
```java
var networks = client.getNodes().get("pve1").getNetwork().index();
for (var net : networks.getData()) {
    if ("bridge".equals(net.get("type").asText())) {
        System.out.println("Bridge: " + net.get("iface").asText());
    }
}
```

---

For more details on specific parameters and options, refer to the [Proxmox VE API Documentation](https://pve.proxmox.com/pve-docs/api-viewer/).
