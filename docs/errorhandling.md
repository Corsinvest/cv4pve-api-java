# Error Handling

This document covers error handling strategies in cv4pve-api-java.

## Understanding Error Types

The Proxmox VE API can return different types of errors that need to be handled appropriately:

- **HTTP Errors**: Network-level errors (4xx, 5xx status codes)
- **API Errors**: Application-level errors from Proxmox VE
- **Connection Errors**: Network connectivity issues
- **Client Errors**: Problems with request formatting

## HTTP Errors

HTTP errors are indicated by the HTTP status code. Always check `isSuccessStatusCode()`:

```java
var result = client.getNodes().get("pve1").getQemu().get(999).getStatus().current();

if (!result.isSuccessStatusCode()) {
    switch (result.getStatusCode()) {
        case 401:
            System.err.println("Authentication failed - check credentials");
            break;
        case 403:
            System.err.println("Permission denied - insufficient privileges");
            break;
        case 404:
            System.err.println("Resource not found - check resource ID");
            break;
        case 429:
            System.err.println("Rate limit exceeded - wait before retrying");
            break;
        case 500:
            System.err.println("Internal server error - Proxmox VE issue");
            break;
        case 502:
            System.err.println("Bad gateway - connection issue");
            break;
        case 503:
            System.err.println("Service unavailable - Proxmox VE overloaded");
            break;
        default:
            System.err.println("HTTP Error " + result.getStatusCode() + ": " + result.getReasonPhrase());
            break;
    }
}
```

## API Errors

API errors come from Proxmox VE itself and are separate from HTTP errors:

```java
var result = client.getNodes().get("pve1").getQemu().get(100)
    .getConfig().updateVm(Map.of("memory", 999999999)); // Invalid memory value

if (result.responseInError()) {
    System.err.println("API Error: " + result.getError());
    // Example output: "Parameter verification failed. memory: value too large"
    // Or: "VM 100 not running"
}
```

## Connection Errors

Handle network-level exceptions:

```java
try {
    var client = new PveClient("invalid-host.com", 8006);
    client.login("root", "password", "pam");
} catch (Exception e) {
    System.err.println("Connection error: " + e.getMessage());
    e.printStackTrace();
}
```

## Comprehensive Error Handling

Best practice for handling all types of errors:

```java
public void createVm(String nodeName, int vmid, String name) {
    try {
        var result = client.getNodes().get(nodeName).getQemu().createVm(vmid, name, 512, 1);

        if (result.isSuccessStatusCode()) {
            if (!result.responseInError()) {
                System.out.println("VM created successfully");
            } else {
                System.err.println("API Error: " + result.getError());
            }
        } else {
            System.err.println("HTTP Error " + result.getStatusCode() + ": " + result.getReasonPhrase());
        }
    } catch (Exception e) {
        System.err.println("Unexpected error: " + e.getMessage());
        e.printStackTrace();
    }
}
```

## Retry Logic for Transient Errors

Implement retry logic for transient failures:

```java
public Result retryOperation(java.util.function.Supplier<Result> operation, int maxRetries) {
    int retries = 0;
    while (retries < maxRetries) {
        var result = operation.get();

        // If successful, return the result
        if (result.isSuccessStatusCode() && !result.responseInError()) {
            return result;
        }

        // Don't retry on certain error codes
        int statusCode = result.getStatusCode();
        if (statusCode == 400 || statusCode == 401 || statusCode == 403 || statusCode == 404) {
            return result; // Don't retry for client errors
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
```

## Logging Errors

For production applications, use proper logging:

```java
import java.util.logging.Logger;
import java.util.logging.Level;

private static final Logger logger = Logger.getLogger(ProxmoxManager.class.getName());

public void handleApiCall() {
    var result = client.getCluster().getStatus().getStatus();

    if (!result.isSuccessStatusCode()) {
        logger.log(Level.SEVERE, "HTTP Error {0}: {1}",
                  new Object[]{result.getStatusCode(), result.getReasonPhrase()});
    } else if (result.responseInError()) {
        logger.severe("API Error: " + result.getError());
    } else {
        logger.info("API call successful");
    }
}
```

## Best Practices

1. **Always check `isSuccessStatusCode()`** before accessing response data
2. **Handle both HTTP and API errors** separately
3. **Use appropriate logging** for different error types
4. **Provide meaningful error messages** to users
5. **Implement retry logic** for transient failures
6. **Validate input parameters** before making API calls
7. **Set appropriate timeouts** to prevent hanging connections
8. **Clean up resources** properly in error scenarios

For more details, see [API Documentation](./api.md#error-handling).
