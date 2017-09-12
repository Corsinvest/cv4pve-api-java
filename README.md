# eve2pve-api-java
ProxmoVE Client API JAVA

General
------------

The client is generated from a JSON Api on ProxmoxVE.
The result is a complete response from server and converted in JSONObject.

[ProxmoxVE Api](https://pve.proxmox.com/pve-docs/api-viewer/)

Usage
-----

```java

Client client = new Client("192.168.22", 8006);
client.login("root", "password", "pam");

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