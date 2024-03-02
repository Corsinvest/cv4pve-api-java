# cv4pve-api-java

Proxmox VE Client API Java

![GitHub release](https://img.shields.io/github/release/Corsinvest/cv4pve-api-java.svg)

[Proxmox VE Api](https://pve.proxmox.com/pve-docs/api-viewer/)

```text
   ______                _                      __
  / ____/___  __________(_)___ _   _____  _____/ /_
 / /   / __ \/ ___/ ___/ / __ \ | / / _ \/ ___/ __/
/ /___/ /_/ / /  (__  ) / / / / |/ /  __(__  ) /_
\____/\____/_/  /____/_/_/ /_/|___/\___/____/\__/

Corsinvest for Proxmox VE Api Client  (Made in Italy)
```

## Copyright and License

Copyright: Corsinvest Srl
For licensing details please visit [LICENSE](LICENSE)

## Commercial Support

This software is part of a suite of tools called cv4pve-tools. If you want commercial support, visit the [site](https://www.corsinvest.it/cv4pve)

## General

The client is generated from a JSON Api on Proxmox VE.

## Result

The result is class **Result** and contain methods:

* **getResponse()** returned from Proxmox VE (data,errors,...) JSONObject .
* **responseInError** (bool) : Contains errors from Proxmox VE.
* **getStatusCode()** (int) : Status code of the HTTP response.
* **getReasonPhrase()** (string): The reason phrase which typically is sent by servers together with the status code.
* **isSuccessStatusCode()** (bool) : Gets a value that indicates if the HTTP response was successful.
* **getError()** (string) : Get error.

## Main features

* Easy to learn
* Method named
* Implementation respect the [Api structure of Proxmox VE](https://pve.proxmox.com/pve-docs/api-viewer/)
* Full method generated from documentation
* Comment any method and parameters
* Parameters indexed eg [n] is structured in array index and value
* Tree structure
  * client.getNodes().get("pve1").getQemu().vmlist().getResponse().getJSONArray("data")
* Return data Proxmox VE
* Debug Level show to console information
* Return result
  * Request
  * Response
  * Status
* Last result action
* Wait task finish task
  * waitForTaskToFinish
  * taskIsRunning
  * getExitStatusTask
* Method directly access
  * get
  * set
  * create
  * delete
* Login return bool if access
* Return Result class more information
* Minimal dependency library
* ClientBase lite function
* Form Proxmox VE 6.2 support Api Token for user
* Login with One-time password for Two-factor authentication
* Support for Proxy
* Set Timeout for the Connection.

## Api token

From version 6.2 of Proxmox VE is possible to use [Api token](https://pve.proxmox.com/pve-docs/pveum-plain.html).
This feature permit execute Api without using user and password.
If using **Privilege Separation** when create api token remember specify in permission.
Format USER@REALM!TOKENID=UUID

## Usage

```java
//if you want use lite version only get/set/create/delete use PveClientBase

PveClient client = new PveClient("10.92.90.91", 8006);
if (client.login("root", "password", "pam")) {
        //version
        System.out.println(client.getVersion().version().getResponse().get("data"));

        // same for put/post/delete
        //loop nodes for
        JSONArray nodes = client.getNodes().index().getResponse().getJSONArray("data");
        for (int i = 0; i < nodes.length(); i++) {
                System.out.println(nodes.get(i));
        }

        //loop nodes for each
        PveClient.<JSONObject>JSONArrayToList(client.getNodes().index().getResponse().getJSONArray("data")).forEach((node) -> {
                System.out.println(node);
        });

        //loops vms qemu
        JSONArray vms = client.getNodes().get("pve1").getQemu().vmlist().getResponse().getJSONArray("data");
        for (int i = 0; i < vms.length(); i++) {
                System.out.println(vms.get(i));
        }

        //loop snapshots
        JSONArray snapshots = client.getNodes().get("pve1")
                .getQemu().get(100).getSnapshot().snapshotList().getResponse().getJSONArray("data");
        for (int i = 0; i < snapshots.length(); i++) {
                System.out.println(snapshots.get(i));
        }

        //create snapshot
        JSONObject retCreateSnap = client.getNodes().get("pve1").getQemu().get(100).getSnapshot().snapshot("pippo").getResponse();

        //print UPID
        System.out.println(retCreateSnap.get("data"));

        //wait creation
        client.waitForTaskToFinish("pve1", retCreateSnap.getString("data"), 500, 10000);

        //delete snapshot
        Result retDeleSnap = client.getNodes().get("pve1").getQemu().get(100).getSnapshot().get("pippo").delsnapshot();
        System.out.println(retDeleSnap.getResponse().get("data"));
}
```
