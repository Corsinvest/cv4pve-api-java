# Result Handling

This document explains how to work with the `Result` class that wraps all API responses.

## The Result Class

All API calls return a `Result` object containing HTTP status, response data, and error information.

```java
var result = client.getNodes().index();
```

## Result Properties and Methods

```java
// Get response data (JsonNode with "data", "errors", etc.)
JsonNode response = result.getResponse();

// Access the data array/object
JsonNode data = response.get("data");

// Check for errors
boolean hasError = result.responseInError();
String errorMessage = result.getError();

// HTTP status information
int statusCode = result.getStatusCode();
String reasonPhrase = result.getReasonPhrase();
boolean isSuccess = result.isSuccessStatusCode();
```

## Checking for Success

```java
var result = client.getNodes().get("pve1").getQemu().get(100).getStatus().current();

if (result.isSuccessStatusCode() && !result.responseInError()) {
    // Success - process data
    JsonNode data = result.getData();
    System.out.println("VM Status: " + data.get("status").asText());
} else if (result.responseInError()) {
    // API error
    System.err.println("API Error: " + result.getError());
} else {
    // HTTP error
    System.err.println("HTTP Error " + result.getStatusCode() + ": " + result.getReasonPhrase());
}
```

## Processing Response Data

```java
// List operations
var result = client.getNodes().get("pve1").getQemu().vmlist();
JsonNode vms = result.getData();

for (JsonNode vm : vms) {
    System.out.println("VM " + vm.get("vmid").asInt() + ": " + vm.get("name").asText());
}
```

For more details, see [API Documentation](./api.md#result-handling).
