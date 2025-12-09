
/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: GPL-3.0-only
 */

package it.corsinvest.proxmoxve.api;

import java.util.logging.Level;
import java.util.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;

public class Test {
    public static void main(String[] args) throws PveExceptionAuthentication {

        System.out.println("Starting PVE Client Test");

        // Configure logging to see debug output
        Logger.getLogger("it.corsinvest.proxmoxve.api").setLevel(Level.FINER);

        var password = System.getenv("PVE_PASSWORD");
        if (password == null || password.isEmpty()) {
            System.err.println("Error: PVE_PASSWORD environment variable not set");
            System.exit(1);
        }

        var client = new PveClient("192.168.0.1", 8006);
        if (client.login("root", password)) {
            // version
            System.out.println(client.getVersion().version().getData());

            // same for put/post/delete
            // loop nodes for
            var nodes = client.getNodes().index().getData();
            for (JsonNode node : nodes) {
                System.out.println(node);
            }

            // List<Object> commands = new ArrayList<>();
            // commands.add("powershell");
            // commands.add("-command");
            // commands.add("echo");
            // commands.add("test");

            // client.getNodes().get("cc01").getQemu().get(1006).getAgent().getExec().exec(commands);

            String nodeId = "cc01";

            // loops vms qemu
            var vms = client.getNodes().get(nodeId).getQemu().vmlist().getData();
            for (JsonNode vm : vms) {
                System.out.println("VM:");
                System.out.println(vm);

                var vmId = vm.get("vmid").asLong();

                System.out.println("    Snapshots for VMID " + vmId + ":");

                var snapshots = client.getNodes().get(nodeId).getQemu().get(vmId).getSnapshot().snapshotList()
                        .getData();
                for (JsonNode snapshot : snapshots) {
                    System.out.println(snapshot);
                }
            }

            // loop snapshots

            // //create snapshot
            // client.getNodes().get(nodeId).getQemu().get(100).getSnapshot().snapshot("pippo");
            // JsonNode retCreateSnap =
            // client.getNodes().get(nodeId).getQemu().get(100).getSnapshot().snapshot("pippo").getResponse();

            // //print UPID
            // System.out.println(retCreateSnap.get("data"));

            // //wait creation
            // client.waitForTaskToFinish(retCreateSnap.get("data").asText(), 500, 10000);

            // //delete snapshot
            // Result retDeleSnap =
            // client.getNodes().get(nodeId).getQemu().get(100).getSnapshot().get("pippo").delsnapshot();
            // System.out.println(retDeleSnap.getData());
        }
    }
}
