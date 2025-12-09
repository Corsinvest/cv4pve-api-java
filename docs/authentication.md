# Authentication Guide

This guide covers all authentication methods available for connecting to Proxmox VE.

## Authentication Methods

### **API Token (Recommended)**

API tokens are the most secure method for automation and applications.

```java
var client = new PveClient("pve.example.com", 8006);

// Set API token (no login() call needed)
client.setApiToken("user@realm!tokenid=uuid");

// Ready to use
var version = client.getVersion().version();
```

**Format:** `USER@REALM!TOKENID=UUID`

**Example:** `automation@pve!api-token=12345678-1234-1234-1234-123456789abc`

### **Username/Password**

Traditional authentication with username and password.

```java
var client = new PveClient("pve.example.com", 8006);

// Basic login
boolean success = client.login("root", "password");

// Login with specific realm
boolean success = client.login("admin@pve", "password");

// Login with PAM realm (default)
boolean success = client.login("user@pam", "password");
```

### **Two-Factor Authentication (2FA)**

For accounts with Two-Factor Authentication enabled.

```java
var client = new PveClient("pve.example.com", 8006);

// Login with TOTP/OTP code
boolean success = client.login("admin@pve", "password", "pve", "123456");

// The fourth parameter is the 6-digit code from your authenticator app
```

---

## Creating API Tokens

### **Via Proxmox VE Web Interface**

1. **Login** to Proxmox VE web interface
2. **Navigate** to Datacenter → Permissions → API Tokens
3. **Click** "Add" button
4. **Configure** token:
   - **User:** Select user (e.g., `root@pam`)
   - **Token ID:** Choose name (e.g., `api-automation`)
   - **Privilege Separation:** Uncheck for full user permissions
   - **Comment:** Optional description
5. **Click** "Add" and **copy the token** (you won't see it again!)

### **Via Command Line**

```bash
# Create API token
pveum user token add root@pam api-automation --privsep=0

# List tokens
pveum user token list root@pam

# Remove token
pveum user token remove root@pam api-automation
```

### **Example Token Creation**

```bash
# Create token for automation user
pveum user add automation@pve --password "secure-password"
pveum user token add automation@pve api-token --privsep=0 --comment "API automation"

# Grant necessary permissions
pveum aclmod / -user automation@pve -role Administrator
```

---

## Security Best Practices

### **DO's**

```java
// Use API tokens for automation
client.setApiToken(System.getenv("PROXMOX_API_TOKEN"));

// Store credentials securely
var username = System.getenv("PROXMOX_USER");
var password = System.getenv("PROXMOX_PASS");

// Enable SSL validation in production
var client = new PveClient("pve.company.com", 8006);
client.setValidateCertificate(true);

// Use specific user accounts (not root)
client.login("automation@pve", password);
```

### **DON'Ts**

```java
// Don't hardcode credentials
client.login("root", "password123"); // Bad!

// Don't disable SSL validation in production
client.setValidateCertificate(false); // Only for development!

// Don't use overly permissive tokens
// Create tokens with minimal required permissions
```

---

## Permission Management

### **Creating Dedicated Users**

```bash
# Create user for API access
pveum user add api-user@pve --password "secure-password" --comment "API automation user"

# Create custom role with specific permissions
pveum role add ApiUser -privs "VM.Audit,VM.Config.Disk,VM.Config.Memory,VM.PowerMgmt,VM.Snapshot"

# Assign role to user
pveum aclmod / -user api-user@pve -role ApiUser
```

### **Common Permission Sets**

```bash
# Read-only access
pveum role add ReadOnly -privs "VM.Audit,Datastore.Audit,Sys.Audit"

# VM management
pveum role add VMManager -privs "VM.Audit,VM.Config.Disk,VM.Config.Memory,VM.PowerMgmt,VM.Snapshot,VM.Clone"

# Full administrator (use with caution)
pveum aclmod / -user user@pve -role Administrator
```

---

## Environment Configuration

### **Environment Variables**

```bash
# Set environment variables
export PROXMOX_HOST="pve.example.com"
export PROXMOX_API_TOKEN="user@pve!token=uuid"

# Or for username/password
export PROXMOX_USER="admin@pve"
export PROXMOX_PASS="secure-password"
```

### **Application Configuration**

```java
import java.util.Properties;
import java.io.FileInputStream;

// Load from properties file
var config = new Properties();
config.load(new FileInputStream("config.properties"));

var client = new PveClient(config.getProperty("proxmox.host"), 8006);

// Use API token if available
var apiToken = config.getProperty("proxmox.apiToken");
if (apiToken != null && !apiToken.isEmpty()) {
    client.setApiToken(apiToken);
} else {
    // Fallback to username/password
    var username = config.getProperty("proxmox.username");
    var password = config.getProperty("proxmox.password");
    client.login(username, password);
}
```

### **Configuration File Example**

```properties
# config.properties
proxmox.host=pve.example.com
proxmox.apiToken=user@pve!token=uuid
proxmox.validateCertificate=true
proxmox.timeout=120000
```

---

## Troubleshooting Authentication

### **Common Issues**

#### **"Authentication Failed"**
```java
// Check credentials
try {
    boolean success = client.login("user@pam", "password");
    if (!success) {
        System.out.println("Invalid credentials");
    }
} catch (PveExceptionAuthentication ex) {
    System.out.println("Login error: " + ex.getMessage());
}
```

#### **"Permission Denied"**
```bash
# Check user permissions
pveum user list
pveum aclmod / -user user@pve -role Administrator
```

#### **"Invalid API Token"**
```java
// Verify token format
client.setApiToken("user@realm!tokenid=uuid"); // Correct format

// Check if token exists
// Token format: USER@REALM!TOKENID=SECRET
```

### **Testing Authentication**

```java
public static boolean testAuthentication(PveClient client) {
    try {
        var version = client.getVersion().version();
        if (version.isSuccessStatusCode()) {
            System.out.println("Authentication successful");
            System.out.println("Connected to Proxmox VE " +
                version.getData().get("version").asText());
            return true;
        } else {
            System.out.println("Authentication failed: " + version.getReasonPhrase());
            return false;
        }
    } catch (Exception ex) {
        System.out.println("Connection error: " + ex.getMessage());
        return false;
    }
}
```

---

## Authentication Examples

### **Enterprise Setup**

```java
// Corporate environment with proxy
var proxy = new Proxy(
    Proxy.Type.HTTP,
    new InetSocketAddress("proxy.company.com", 8080)
);

var client = new PveClient("pve.company.com", 8006);
client.setProxy(proxy);
client.setValidateCertificate(true);
client.setTimeout(300000); // 5 minutes

client.setApiToken(System.getenv("PROXMOX_API_TOKEN"));
```

### **Home Lab Setup**

```java
// Simple home lab setup
var client = new PveClient("192.168.1.100", 8006);
client.setValidateCertificate(false); // Self-signed cert
client.setTimeout(120000); // 2 minutes

client.login("root@pam", System.getenv("PVE_PASSWORD"));
```

### **Cloud/Automation Setup**

```java
// Automated deployment script
var client = new PveClient(System.getenv("PROXMOX_HOST"), 8006);
client.setValidateCertificate(true);

// Use API token for automation
client.setApiToken(System.getenv("PROXMOX_API_TOKEN"));

// Verify connection before proceeding
if (!testAuthentication(client)) {
    System.exit(1);
}
```
