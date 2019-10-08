/*
 * This file is part of the cv4pve-api-java https://github.com/Corsinvest/cv4pve-api-java,
 * Copyright (C) 2016 Corsinvest Srl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import it.corsinvest.proxmoxve.api.PveClient;
import it.corsinvest.proxmoxve.api.Result;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Test {

    public static void main(String[] args) throws JSONException {
        PveClient client = new PveClient("10.92.90.91", 8006);
        if (client.login("test@pam", "test")) {
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
    }
}
