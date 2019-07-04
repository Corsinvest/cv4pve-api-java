
import it.corsinvest.proxmoxve.api.Client;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Test {

    public static void main(String[] args) throws JSONException {
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
    }
}
