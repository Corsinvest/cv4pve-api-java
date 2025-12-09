# Task Management

This document explains how to manage long-running operations in Proxmox VE.

## Task UPID

Many operations return a task UPID (Unique Process ID):

```java
var result = client.getNodes().get("pve1")
    .getQemu().get(100).getStatus().start();

String upid = result.getData().asText();
System.out.println("Task UPID: " + upid);
```

## Wait for Task Completion

```java
// waitForTaskToFinish(node, upid, wait_interval_ms, timeout_ms)
boolean completed = client.waitForTaskToFinish("pve1", upid, 500, 30000);

if (completed) {
    System.out.println("Task completed successfully");
} else {
    System.out.println("Task did not complete within timeout");
}
```

## Check Task Status

```java
// Check if task is still running
boolean isRunning = client.taskIsRunning("pve1", upid);

// Get task exit status
String exitStatus = client.getExitStatusTask("pve1", upid);
System.out.println("Exit status: " + exitStatus); // "OK" or error message
```

## Read Task Log

```java
var logResult = client.getNodes().get("pve1")
    .getTasks().get(upid).getLog().readTaskLog();

if (logResult.isSuccessStatusCode()) {
    var logLines = logResult.getData();
    for (JsonNode line : logLines) {
        System.out.println(line.get("t").asText()); // Log line text
    }
}
```

## Example: Complete Task Management

```java
// Start VM
var startResult = client.getNodes().get("pve1")
    .getQemu().get(100).getStatus().start();

if (startResult.isSuccessStatusCode()) {
    String upid = startResult.getData().asText();
    System.out.println("Starting VM, task: " + upid);

    // Wait for completion
    if (client.waitForTaskToFinish("pve1", upid, 1000, 60000)) {
        String exitStatus = client.getExitStatusTask("pve1", upid);
        if ("OK".equals(exitStatus)) {
            System.out.println("VM started successfully");
        } else {
            System.err.println("Task failed: " + exitStatus);
        }
    } else {
        System.err.println("Task timeout");
    }
}
```

For more details, see [API Documentation](./api.md#task-management).
