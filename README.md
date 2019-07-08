# cv4pve-api-java

ProxmoVE Client API JAVA

[![License](https://img.shields.io/github/license/Corsinvest/cv4pve-api-java.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html) ![GitHub release](https://img.shields.io/github/release/Corsinvest/cv4pve-api-java.svg) [![Donate to this project using Paypal](https://img.shields.io/badge/paypal-donate-yellow.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=PPM9JHLQLRV2S&item_name=Open+Source+Project&currency_code=EUR&source=url)


[ProxmoxVE Api](https://pve.proxmox.com/pve-docs/api-viewer/)

```text
   ______                _                      __
  / ____/___  __________(_)___ _   _____  _____/ /_
 / /   / __ \/ ___/ ___/ / __ \ | / / _ \/ ___/ __/
/ /___/ /_/ / /  (__  ) / / / / |/ /  __(__  ) /_
\____/\____/_/  /____/_/_/ /_/|___/\___/____/\__/

Corsinvest for Proxmox VE Api Client  (Made in Italy)
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
* Debug Level show to console information
* Return result status
  * getStatusCode
  * getReasonPhrase
  * isSuccessStatusCode
* Wait task finish task
  * waitForTaskToFinish
  * taskIsRunning
  * getExitStatusTask
* Method directry access
  * get
  * set
  * create
  * delete
* Login return bool if access
* Return Result class more information
* Minimal dependency library

## Usage

```java
Client client = new Client("10.92.90.91", 8006);
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
        Client.<JSONObject>JSONArrayToList(client.getNodes().index().getResponse().getJSONArray("data")).forEach((node) -> {
                System.out.println(node);
        });

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
        JSONObject retCreateSnap = client.getNodes().get("pve1").getQemu().get(100).getSnapshot().snapshot("pippo").getResponse();

        //print UPID
        System.out.println(retCreateSnap.get("data"));

        //wait creation
        client.waitForTaskToFinish("pve1", retCreateSnap.getString("data"), 500, 10000);

        //delete snapshot
        Client.Result retDeleSnap = client.getNodes().get("pve1").getQemu().get(100).getSnapshot().get("pippo").delsnapshot();
        System.out.println(retDeleSnap.getResponse().get("data"));
}
```

[![paypal](https://www.paypalobjects.com/en_US/IT/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=PPM9JHLQLRV2S&item_name=Open+Source+Project&currency_code=EUR&source=url)
