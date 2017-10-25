# eve2pve-api-java

ProxmoVE Client API JAVA

[ProxmoxVE Api](https://pve.proxmox.com/pve-docs/api-viewer/)

```text
    ______      __                       _              _    ________
   / ____/___  / /____  _________  _____(_)_______     | |  / / ____/
  / __/ / __ \/ __/ _ \/ ___/ __ \/ ___/ / ___/ _ \    | | / / __/
 / /___/ / / / /_/  __/ /  / /_/ / /  / (__  )  __/    | |/ / /___
/_____/_/ /_/\__/\___/_/  / .___/_/  /_/____/\___/     |___/_____/
                         /_/

                                                       (Made in Italy)
```

## General

The client is generated from a JSON Api on ProxmoxVE.

## Result

The result is class **Result** and contain methods:

* **getResponse()** returned from ProxmoxVE (data,errors,...) JSONObject
* **responseInError** (bool) : Contains errors from ProxmoxVE.
* **getStatusCode()** (int) : Status code of the HTTP response.
* **getReasonPhrase()** (string): The reason phrase which typically is sent by servers together with the status code.
* **isSuccessStatusCode()** (bool) : Gets a value that indicates if the HTTP response was successful.
* **getError()** (string) : Get error.

## Main features

* Easy to learn
* Method named
* Method no named rest (same parameters)
  * getRest
  * setRest
  * createRest
  * deleteRest
* Full method generated from documentation
* Comment any method and parameters
* Parameters indexed eg [n] is structured in array index and value
* Tree structure
  * client.getNodes().get("pve1").getQemu().vmlist().getResponse().getJSONArray("data")
* Return data Proxmox VE
* Return result status
  * getStatusCode
  * getReasonPhrase
  * isSuccessStatusCode
* Wait task finish task
  * waitForTaskToFinish
* Method directry access
  * get
  * set
  * create
  * delete
* Login return bool if access
* Return Result class more information

## Usage

```java

Client client = new Client("192.168.22", 8006);
client.login("root", "password", "pam");

System.out.println(client->get('/version'));
// same for put/post/delete

//loop nodes for
JSONArray nodes = client.getNodes().index().getResponse().getJSONArray("data");
for (int i = 0; i < nodes.length(); i++) {
    System.out.println(nodes.get(i));
}

//loop nodes for each
for (JSONObject node : Client.<JSONObject>JSONArrayToList(client.getNodes().index().getResponse().getJSONArray("data"))) {
    System.out.println(node);
}

 //loops vms qemu
JSONArray vms = client.getNodes().get("pve1").getQemu().vmlist().getResponse().getJSONArray("data");
for (int i = 0; i < vms.length(); i++) {
    System.out.println(vms.get(i));
}

 //loop snashots
JSONArray snapshots = client.getNodes().get("pve1")
    .getQemu().get(100).getSnapshot().snapshotList().getResponse().getJSONArray("data");
for (int i = 0; i < snapshots.length(); i++) {
    System.out.println(snapshots.get(i));
}

//create snapshot
JSONObject retCreateSnap = client.getNodes().get("pve1")
    .getQemu().get(100).getSnapshot().snapshot("pippo").getResponse();

//print UPID
System.out.println(retCreateSnap.get("data"));

//wait creation
client.waitForTaskToFinish("pve1", retCreateSnap.getString("data"), 500, 10000);

//delete snapshot
Client.Result retDeleSnap = client.getNodes().get("pve1")
    .getQemu().get(100).getSnapshot().get("pippo").delsnapshot();
System.out.println(retDeleSnap.getResponse().get("data"));
```
