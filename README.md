#eve2pve-api-java
ProxmoVE Client API JAVA

[ProxmoxVE Api](https://pve.proxmox.com/pve-docs/api-viewer/)

# General

The client is generated from a JSON Api on ProxmoxVE.
The result is a complete response from server and converted in JSONObject.

# Main features
* Easy to learn
* Method named
* Full method generated from documentation
* Comment any method and parameters
* Parameters indexed eg [n] is structured in array index and value
* Tree structure
    * client.getNodes().get("pve1").getQemu().vmlist().getJSONArray("data")
* Return data proxmox
* Return result status
    * getStatusCode
    * getReasonPhrase
* Method directry access
    * get
    * post
    * put
    * delete
* login return bool if access

# Usage

```java

Client client = new Client("192.168.22", 8006);
client.login("root", "password", "pam");

System.out.println(client->get('/version'));
// same for put/post/delete

//loop nodes for
JSONArray nodes = client.getNodes().index().getJSONArray("data");
for (int i = 0; i < nodes.length(); i++) {
    System.out.println(nodes.get(i));
}

//loop nodes for each
for (JSONObject node : Client.<JSONObject>JSONArrayToList(client.getNodes().index().getJSONArray("data"))) {
    System.out.println(node);
}

 //loops vms qemu
 JSONArray vms = client.getNodes().get("pve1").getQemu().vmlist().getJSONArray("data");
 for (int i = 0; i < vms.length(); i++) {
     System.out.println(vms.get(i));
 }

 //loop snashot
 JSONArray snapshots = client.getNodes().get("pve1")
         .getQemu().get(100).getSnapshot().snapshotList().getJSONArray("data");
 for (int i = 0; i < snapshots.length(); i++) {
     System.out.println(snapshots.get(i));
 }

 //create snapshot
 JSONObject retCreateSnap = client.getNodes().get("pve1")
         .getQemu().get(100).getSnapshot().snapshot("pippo");
 System.out.println(retCreateSnap.get("data"));

 //delete snapshot
 JSONObject retDeleSnap = client.getNodes().get("pve1")
         .getQemu().get(100).getSnapshot().get("pippo").delsnapshot();
 System.out.println(retDeleSnap.get("data"));
```