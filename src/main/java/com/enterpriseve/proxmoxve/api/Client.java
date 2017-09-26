package com.enterpriseve.proxmoxve.api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

/**
 * ProxmoxVE Client
 */
public class Client {

    private String _ticketCSRFPreventionToken;
    private String _ticketPVEAuthCookie;
    private Client _client;
    private final String _hostName;
    private final int _port;
    private int _statusCode;
    private String _reasonPhrase;

    public Client(String hostName, int port) {
        _client = this;
        _hostName = hostName;
        _port = port;
    }

    public String getHostName() {
        return _hostName;
    }

    public int getPort() {
        return _port;
    }

    /**
     * Creation ticket from login.
     *
     * @param userName user name or <username>@<relam>
     * @param password
     * @return
     * @throws JSONException
     */
    public boolean login(String userName, String password) throws JSONException {
        String realm = "pam";
        String[] uData = userName.split("@");
        if (uData.length > 1) {
            userName = uData[0];
            realm = uData[1];
        }

        return login(userName, password, realm);
    }

    /**
     * Creation ticket from login.
     *
     * @param userName user name
     * @param password
     * @param realm pam/pve or custom
     * @return
     * @throws JSONException
     */
    public boolean login(String userName, String password, String realm) throws JSONException {
        JSONObject ticket = getAccess().getTicket().createTicket(password, userName, null, null, null, realm);
        if (ticket != null && !ticket.isNull("data")) {
            _ticketCSRFPreventionToken = ticket.getJSONObject("data").getString("CSRFPreventionToken");
            _ticketPVEAuthCookie = ticket.getJSONObject("data").getString("ticket");
            return true;
        } else {
            return false;
        }
    }

    public String getReasonPhrase() {
        return _reasonPhrase;
    }

    public int getStatusCode() {
        return _statusCode;
    }

    private enum HttpMethod {
        GET, POST, PUT, DELETE
    }

    public JSONObject get(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, HttpMethod.GET, parameters);
    }

    public JSONObject put(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, HttpMethod.PUT, parameters);
    }

    public JSONObject post(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, HttpMethod.POST, parameters);
    }

    public JSONObject delete(String resource, Map<String, Object> parameters) throws JSONException {
        return executeAction(resource, HttpMethod.DELETE, parameters);
    }

    private JSONObject executeAction(String resource, HttpMethod method, Map<String, Object> parameters) throws JSONException {
        String url = "https://" + _hostName + ":" + _port + "/api2/json" + resource;
        //fix parms
        ArrayList<NameValuePair> parms = new ArrayList<NameValuePair>();
        if (parameters != null) {
            for (Map.Entry<String, Object> entry : parameters.entrySet()) {
                if (entry.getValue() != null) {
                    String value = entry.getValue().toString();
                    if (entry.getValue() instanceof Boolean) {
                        value = ((Boolean) entry.getValue()) ? "1" : "0";
                    }
                    try {
                        parms.add(new BasicNameValuePair(entry.getKey(), URLEncoder.encode(value, "UTF-8")));
                    } catch (UnsupportedEncodingException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        }
        HttpRequestBase request = null;
        switch (method) {
            case GET: {
                if (!parms.isEmpty()) {
                    StringBuilder urlParms = new StringBuilder();
                    for (NameValuePair parm : parms) {
                        urlParms.append(urlParms.length() > 1 ? "&" : "")
                                .append(parm.getName())
                                .append("=")
                                .append(parm.getValue());
                    }
                    url += "?" + urlParms.toString();
                }
                request = new HttpGet(url);
                break;
            }
            case POST: {
                request = new HttpPost(url);
                try {
                    ((HttpPost) request).setEntity(new UrlEncodedFormEntity(parms));
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
                break;
            }
            case PUT: {
                request = new HttpPut(url);
                try {
                    ((HttpPut) request).setEntity(new UrlEncodedFormEntity(parms));
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
                break;
            }
            case DELETE: {
                request = new HttpDelete(url);
                break;
            }
        }
        if (_ticketCSRFPreventionToken != null) {
            request.addHeader("CSRFPreventionToken", _ticketCSRFPreventionToken);
            request.addHeader("Cookie", "PVEAuthCookie=" + _ticketPVEAuthCookie);
        }
        HttpClient client = new DefaultHttpClient();
        try {
            SSLSocketFactory sslsf = new SSLSocketFactory(new TrustSelfSignedStrategy(),
                    new AllowAllHostnameVerifier());
            Scheme https = new Scheme("https", _port, sslsf);
            client.getConnectionManager().getSchemeRegistry().register(https);
        } catch (KeyManagementException | KeyStoreException
                | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        HttpResponse httpResponse;
        JSONObject response = null;
        try {
            httpResponse = client.execute(request);
            _statusCode = httpResponse.getStatusLine().getStatusCode();
            _reasonPhrase = httpResponse.getStatusLine().getReasonPhrase();
            HttpEntity entity = httpResponse.getEntity();
            if (entity != null) {
                InputStream instream = entity.getContent();
                String data = convertStreamToString(instream);
                response = new JSONObject(data);
                // Closing the input stream will trigger connection release
                instream.close();
            }
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (JSONException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        return response;
    }

    private static String convertStreamToString(InputStream is) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line = null;
        try {
            while ((line = reader.readLine()) != null) {
                sb.append(line + "\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return sb.toString();
    }

    protected static void addIndexedParmeter(Map<String, Object> parameters, String name, Map<Integer, String> value) {
        for (Map.Entry<Integer, String> entry : value.entrySet()) {
            parameters.put(name + entry.getKey(), entry.getValue());
        }
    }

    public static <T> List<T> JSONArrayToList(JSONArray array) throws JSONException {
        List<T> ret = new ArrayList<>();
        if (array != null) {
            for (int i = 0; i < array.length(); i++) {
                ret.add((T) array.get(i));
            }
        }
        return ret;
    }

    public abstract class Base {

        private Client _client;
    }
    private PVECluster _cluster;

    public PVECluster getCluster() {
        if (_cluster == null) {
            _cluster = new PVECluster(_client);
        }
        return _cluster;
    }
    private PVENodes _nodes;

    public PVENodes getNodes() {
        if (_nodes == null) {
            _nodes = new PVENodes(_client);
        }
        return _nodes;
    }
    private PVEStorage _storage;

    public PVEStorage getStorage() {
        if (_storage == null) {
            _storage = new PVEStorage(_client);
        }
        return _storage;
    }
    private PVEAccess _access;

    public PVEAccess getAccess() {
        if (_access == null) {
            _access = new PVEAccess(_client);
        }
        return _access;
    }
    private PVEPools _pools;

    public PVEPools getPools() {
        if (_pools == null) {
            _pools = new PVEPools(_client);
        }
        return _pools;
    }
    private PVEVersion _version;

    public PVEVersion getVersion() {
        if (_version == null) {
            _version = new PVEVersion(_client);
        }
        return _version;
    }

    public class PVECluster extends Base {

        protected PVECluster(Client client) {
            _client = client;
        }
        private PVEReplication _replication;

        public PVEReplication getReplication() {
            if (_replication == null) {
                _replication = new PVEReplication(_client);
            }
            return _replication;
        }
        private PVEConfig _config;

        public PVEConfig getConfig() {
            if (_config == null) {
                _config = new PVEConfig(_client);
            }
            return _config;
        }
        private PVEFirewall _firewall;

        public PVEFirewall getFirewall() {
            if (_firewall == null) {
                _firewall = new PVEFirewall(_client);
            }
            return _firewall;
        }
        private PVEBackup _backup;

        public PVEBackup getBackup() {
            if (_backup == null) {
                _backup = new PVEBackup(_client);
            }
            return _backup;
        }
        private PVEHa _ha;

        public PVEHa getHa() {
            if (_ha == null) {
                _ha = new PVEHa(_client);
            }
            return _ha;
        }
        private PVELog _log;

        public PVELog getLog() {
            if (_log == null) {
                _log = new PVELog(_client);
            }
            return _log;
        }
        private PVEResources _resources;

        public PVEResources getResources() {
            if (_resources == null) {
                _resources = new PVEResources(_client);
            }
            return _resources;
        }
        private PVETasks _tasks;

        public PVETasks getTasks() {
            if (_tasks == null) {
                _tasks = new PVETasks(_client);
            }
            return _tasks;
        }
        private PVEOptions _options;

        public PVEOptions getOptions() {
            if (_options == null) {
                _options = new PVEOptions(_client);
            }
            return _options;
        }
        private PVEStatus _status;

        public PVEStatus getStatus() {
            if (_status == null) {
                _status = new PVEStatus(_client);
            }
            return _status;
        }
        private PVENextid _nextid;

        public PVENextid getNextid() {
            if (_nextid == null) {
                _nextid = new PVENextid(_client);
            }
            return _nextid;
        }

        public class PVEReplication extends Base {

            protected PVEReplication(Client client) {
                _client = client;
            }

            public PVEItemId get(Object id) {
                return new PVEItemId(_client, id);
            }

            public class PVEItemId extends Base {

                private Object _id;

                protected PVEItemId(Client client, Object id) {
                    _client = client;
                    _id = id;
                }

                /**
                 * Mark replication job for removal.
                 *
                 * @param force Will remove the jobconfig entry, but will not
                 * cleanup.
                 * @param keep Keep replicated data at target (do not remove).
                 */
                public void delete(Boolean force, Boolean keep) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("force", force);
                    parameters.put("keep", keep);
                    _client.delete("/cluster/replication/" + _id + "", parameters);
                }

                /**
                 * Mark replication job for removal.
                 */
                public void delete() throws JSONException {
                    _client.delete("/cluster/replication/" + _id + "", null);
                }

                /**
                 * Read replication job configuration.
                 */
                public JSONObject read() throws JSONException {
                    return _client.get("/cluster/replication/" + _id + "", null);
                }

                /**
                 * Update replication job configuration.
                 *
                 * @param comment Description.
                 * @param delete A list of settings you want to delete.
                 * @param digest Prevent changes if current configuration file
                 * has different SHA1 digest. This can be used to prevent
                 * concurrent modifications.
                 * @param disable Flag to disable/deactivate the entry.
                 * @param rate Rate limit in mbps (megabytes per second) as
                 * floating point number.
                 * @param remove_job Mark the replication job for removal. The
                 * job will remove all local replication snapshots. When set to
                 * 'full', it also tries to remove replicated volumes on the
                 * target. The job then removes itself from the configuration
                 * file. Enum: local,full
                 * @param schedule Storage replication schedule. The format is a
                 * subset of `systemd` calender events.
                 */
                public void update(String comment, String delete, String digest, Boolean disable, Integer rate, String remove_job, String schedule) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("comment", comment);
                    parameters.put("delete", delete);
                    parameters.put("digest", digest);
                    parameters.put("disable", disable);
                    parameters.put("rate", rate);
                    parameters.put("remove_job", remove_job);
                    parameters.put("schedule", schedule);
                    _client.put("/cluster/replication/" + _id + "", parameters);
                }

                /**
                 * Update replication job configuration.
                 */
                public void update() throws JSONException {
                    _client.put("/cluster/replication/" + _id + "", null);
                }
            }

            /**
             * List replication jobs.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/cluster/replication", null);
            }

            /**
             * Create a new replication job
             *
             * @param id Replication Job ID. The ID is composed of a Guest ID
             * and a job number, separated by a hyphen, i.e.
             * '&amp;lt;GUEST&amp;gt;-&amp;lt;JOBNUM&amp;gt;'.
             * @param target Target node.
             * @param type Section type. Enum: local
             * @param comment Description.
             * @param disable Flag to disable/deactivate the entry.
             * @param rate Rate limit in mbps (megabytes per second) as floating
             * point number.
             * @param remove_job Mark the replication job for removal. The job
             * will remove all local replication snapshots. When set to 'full',
             * it also tries to remove replicated volumes on the target. The job
             * then removes itself from the configuration file. Enum: local,full
             * @param schedule Storage replication schedule. The format is a
             * subset of `systemd` calender events.
             */
            public void create(String id, String target, String type, String comment, Boolean disable, Integer rate, String remove_job, String schedule) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("id", id);
                parameters.put("target", target);
                parameters.put("type", type);
                parameters.put("comment", comment);
                parameters.put("disable", disable);
                parameters.put("rate", rate);
                parameters.put("remove_job", remove_job);
                parameters.put("schedule", schedule);
                _client.post("/cluster/replication", parameters);
            }

            /**
             * Create a new replication job
             *
             * @param id Replication Job ID. The ID is composed of a Guest ID
             * and a job number, separated by a hyphen, i.e.
             * '&amp;lt;GUEST&amp;gt;-&amp;lt;JOBNUM&amp;gt;'.
             * @param target Target node.
             * @param type Section type. Enum: local
             */
            public void create(String id, String target, String type) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("id", id);
                parameters.put("target", target);
                parameters.put("type", type);
                _client.post("/cluster/replication", parameters);
            }
        }

        public class PVEConfig extends Base {

            protected PVEConfig(Client client) {
                _client = client;
            }
            private PVENodes _nodes;

            public PVENodes getNodes() {
                if (_nodes == null) {
                    _nodes = new PVENodes(_client);
                }
                return _nodes;
            }
            private PVETotem _totem;

            public PVETotem getTotem() {
                if (_totem == null) {
                    _totem = new PVETotem(_client);
                }
                return _totem;
            }

            public class PVENodes extends Base {

                protected PVENodes(Client client) {
                    _client = client;
                }

                /**
                 * Corosync node list.
                 */
                public JSONObject nodes() throws JSONException {
                    return _client.get("/cluster/config/nodes", null);
                }
            }

            public class PVETotem extends Base {

                protected PVETotem(Client client) {
                    _client = client;
                }

                /**
                 * Get corosync totem protocol settings.
                 */
                public JSONObject totem() throws JSONException {
                    return _client.get("/cluster/config/totem", null);
                }
            }

            /**
             * Directory index.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/cluster/config", null);
            }
        }

        public class PVEFirewall extends Base {

            protected PVEFirewall(Client client) {
                _client = client;
            }
            private PVEGroups _groups;

            public PVEGroups getGroups() {
                if (_groups == null) {
                    _groups = new PVEGroups(_client);
                }
                return _groups;
            }
            private PVERules _rules;

            public PVERules getRules() {
                if (_rules == null) {
                    _rules = new PVERules(_client);
                }
                return _rules;
            }
            private PVEIpset _ipset;

            public PVEIpset getIpset() {
                if (_ipset == null) {
                    _ipset = new PVEIpset(_client);
                }
                return _ipset;
            }
            private PVEAliases _aliases;

            public PVEAliases getAliases() {
                if (_aliases == null) {
                    _aliases = new PVEAliases(_client);
                }
                return _aliases;
            }
            private PVEOptions _options;

            public PVEOptions getOptions() {
                if (_options == null) {
                    _options = new PVEOptions(_client);
                }
                return _options;
            }
            private PVEMacros _macros;

            public PVEMacros getMacros() {
                if (_macros == null) {
                    _macros = new PVEMacros(_client);
                }
                return _macros;
            }
            private PVERefs _refs;

            public PVERefs getRefs() {
                if (_refs == null) {
                    _refs = new PVERefs(_client);
                }
                return _refs;
            }

            public class PVEGroups extends Base {

                protected PVEGroups(Client client) {
                    _client = client;
                }

                public PVEItemGroup get(Object group) {
                    return new PVEItemGroup(_client, group);
                }

                public class PVEItemGroup extends Base {

                    private Object _group;

                    protected PVEItemGroup(Client client, Object group) {
                        _client = client;
                        _group = group;
                    }

                    public PVEItemPos get(Object pos) {
                        return new PVEItemPos(_client, _group, pos);
                    }

                    public class PVEItemPos extends Base {

                        private Object _group;
                        private Object _pos;

                        protected PVEItemPos(Client client, Object group, Object pos) {
                            _client = client;
                            _group = group;
                            _pos = pos;
                        }

                        /**
                         * Delete rule.
                         *
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         */
                        public void deleteRule(String digest) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("digest", digest);
                            _client.delete("/cluster/firewall/groups/" + _group + "/" + _pos + "", parameters);
                        }

                        /**
                         * Delete rule.
                         */
                        public void deleteRule() throws JSONException {
                            _client.delete("/cluster/firewall/groups/" + _group + "/" + _pos + "", null);
                        }

                        /**
                         * Get single rule data.
                         */
                        public JSONObject getRule() throws JSONException {
                            return _client.get("/cluster/firewall/groups/" + _group + "/" + _pos + "", null);
                        }

                        /**
                         * Modify rule data.
                         *
                         * @param action Rule action ('ACCEPT', 'DROP',
                         * 'REJECT') or security group name.
                         * @param comment Descriptive comment.
                         * @param delete A list of settings you want to delete.
                         * @param dest Restrict packet destination address. This
                         * can refer to a single IP address, an IP set
                         * ('+ipsetname') or an IP alias definition. You can
                         * also specify an address range like
                         * '20.34.101.207-201.3.9.99', or a list of IP addresses
                         * and networks (entries are separated by comma). Please
                         * do not mix IPv4 and IPv6 addresses inside such lists.
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         * @param dport Restrict TCP/UDP destination port. You
                         * can use service names or simple numbers (0-65535), as
                         * defined in '/etc/services'. Port ranges can be
                         * specified with '\d+:\d+', for example '80:85', and
                         * you can use comma separated list to match several
                         * ports or ranges.
                         * @param enable Flag to enable/disable a rule.
                         * @param iface Network interface name. You have to use
                         * network configuration key names for VMs and
                         * containers ('net\d+'). Host related rules can use
                         * arbitrary strings.
                         * @param macro Use predefined standard macro.
                         * @param moveto Move rule to new position
                         * &amp;lt;moveto&amp;gt;. Other arguments are ignored.
                         * @param proto IP protocol. You can use protocol names
                         * ('tcp'/'udp') or simple numbers, as defined in
                         * '/etc/protocols'.
                         * @param source Restrict packet source address. This
                         * can refer to a single IP address, an IP set
                         * ('+ipsetname') or an IP alias definition. You can
                         * also specify an address range like
                         * '20.34.101.207-201.3.9.99', or a list of IP addresses
                         * and networks (entries are separated by comma). Please
                         * do not mix IPv4 and IPv6 addresses inside such lists.
                         * @param sport Restrict TCP/UDP source port. You can
                         * use service names or simple numbers (0-65535), as
                         * defined in '/etc/services'. Port ranges can be
                         * specified with '\d+:\d+', for example '80:85', and
                         * you can use comma separated list to match several
                         * ports or ranges.
                         * @param type Rule type. Enum: in,out,group
                         */
                        public void updateRule(String action, String comment, String delete, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer moveto, String proto, String source, String sport, String type) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("action", action);
                            parameters.put("comment", comment);
                            parameters.put("delete", delete);
                            parameters.put("dest", dest);
                            parameters.put("digest", digest);
                            parameters.put("dport", dport);
                            parameters.put("enable", enable);
                            parameters.put("iface", iface);
                            parameters.put("macro", macro);
                            parameters.put("moveto", moveto);
                            parameters.put("proto", proto);
                            parameters.put("source", source);
                            parameters.put("sport", sport);
                            parameters.put("type", type);
                            _client.put("/cluster/firewall/groups/" + _group + "/" + _pos + "", parameters);
                        }

                        /**
                         * Modify rule data.
                         */
                        public void updateRule() throws JSONException {
                            _client.put("/cluster/firewall/groups/" + _group + "/" + _pos + "", null);
                        }
                    }

                    /**
                     * Delete security group.
                     */
                    public void deleteSecurityGroup() throws JSONException {
                        _client.delete("/cluster/firewall/groups/" + _group + "", null);
                    }

                    /**
                     * List rules.
                     */
                    public JSONObject getRules() throws JSONException {
                        return _client.get("/cluster/firewall/groups/" + _group + "", null);
                    }

                    /**
                     * Create new rule.
                     *
                     * @param action Rule action ('ACCEPT', 'DROP', 'REJECT') or
                     * security group name.
                     * @param type Rule type. Enum: in,out,group
                     * @param comment Descriptive comment.
                     * @param dest Restrict packet destination address. This can
                     * refer to a single IP address, an IP set ('+ipsetname') or
                     * an IP alias definition. You can also specify an address
                     * range like '20.34.101.207-201.3.9.99', or a list of IP
                     * addresses and networks (entries are separated by comma).
                     * Please do not mix IPv4 and IPv6 addresses inside such
                     * lists.
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     * @param dport Restrict TCP/UDP destination port. You can
                     * use service names or simple numbers (0-65535), as defined
                     * in '/etc/services'. Port ranges can be specified with
                     * '\d+:\d+', for example '80:85', and you can use comma
                     * separated list to match several ports or ranges.
                     * @param enable Flag to enable/disable a rule.
                     * @param iface Network interface name. You have to use
                     * network configuration key names for VMs and containers
                     * ('net\d+'). Host related rules can use arbitrary strings.
                     * @param macro Use predefined standard macro.
                     * @param pos Update rule at position &amp;lt;pos&amp;gt;.
                     * @param proto IP protocol. You can use protocol names
                     * ('tcp'/'udp') or simple numbers, as defined in
                     * '/etc/protocols'.
                     * @param source Restrict packet source address. This can
                     * refer to a single IP address, an IP set ('+ipsetname') or
                     * an IP alias definition. You can also specify an address
                     * range like '20.34.101.207-201.3.9.99', or a list of IP
                     * addresses and networks (entries are separated by comma).
                     * Please do not mix IPv4 and IPv6 addresses inside such
                     * lists.
                     * @param sport Restrict TCP/UDP source port. You can use
                     * service names or simple numbers (0-65535), as defined in
                     * '/etc/services'. Port ranges can be specified with
                     * '\d+:\d+', for example '80:85', and you can use comma
                     * separated list to match several ports or ranges.
                     */
                    public void createRule(String action, String type, String comment, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer pos, String proto, String source, String sport) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("action", action);
                        parameters.put("type", type);
                        parameters.put("comment", comment);
                        parameters.put("dest", dest);
                        parameters.put("digest", digest);
                        parameters.put("dport", dport);
                        parameters.put("enable", enable);
                        parameters.put("iface", iface);
                        parameters.put("macro", macro);
                        parameters.put("pos", pos);
                        parameters.put("proto", proto);
                        parameters.put("source", source);
                        parameters.put("sport", sport);
                        _client.post("/cluster/firewall/groups/" + _group + "", parameters);
                    }

                    /**
                     * Create new rule.
                     *
                     * @param action Rule action ('ACCEPT', 'DROP', 'REJECT') or
                     * security group name.
                     * @param type Rule type. Enum: in,out,group
                     */
                    public void createRule(String action, String type) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("action", action);
                        parameters.put("type", type);
                        _client.post("/cluster/firewall/groups/" + _group + "", parameters);
                    }
                }

                /**
                 * List security groups.
                 */
                public JSONObject listSecurityGroups() throws JSONException {
                    return _client.get("/cluster/firewall/groups", null);
                }

                /**
                 * Create new security group.
                 *
                 * @param group Security Group name.
                 * @param comment
                 * @param digest Prevent changes if current configuration file
                 * has different SHA1 digest. This can be used to prevent
                 * concurrent modifications.
                 * @param rename Rename/update an existing security group. You
                 * can set 'rename' to the same value as 'name' to update the
                 * 'comment' of an existing group.
                 */
                public void createSecurityGroup(String group, String comment, String digest, String rename) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("group", group);
                    parameters.put("comment", comment);
                    parameters.put("digest", digest);
                    parameters.put("rename", rename);
                    _client.post("/cluster/firewall/groups", parameters);
                }

                /**
                 * Create new security group.
                 *
                 * @param group Security Group name.
                 */
                public void createSecurityGroup(String group) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("group", group);
                    _client.post("/cluster/firewall/groups", parameters);
                }
            }

            public class PVERules extends Base {

                protected PVERules(Client client) {
                    _client = client;
                }

                public PVEItemPos get(Object pos) {
                    return new PVEItemPos(_client, pos);
                }

                public class PVEItemPos extends Base {

                    private Object _pos;

                    protected PVEItemPos(Client client, Object pos) {
                        _client = client;
                        _pos = pos;
                    }

                    /**
                     * Delete rule.
                     *
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     */
                    public void deleteRule(String digest) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("digest", digest);
                        _client.delete("/cluster/firewall/rules/" + _pos + "", parameters);
                    }

                    /**
                     * Delete rule.
                     */
                    public void deleteRule() throws JSONException {
                        _client.delete("/cluster/firewall/rules/" + _pos + "", null);
                    }

                    /**
                     * Get single rule data.
                     */
                    public JSONObject getRule() throws JSONException {
                        return _client.get("/cluster/firewall/rules/" + _pos + "", null);
                    }

                    /**
                     * Modify rule data.
                     *
                     * @param action Rule action ('ACCEPT', 'DROP', 'REJECT') or
                     * security group name.
                     * @param comment Descriptive comment.
                     * @param delete A list of settings you want to delete.
                     * @param dest Restrict packet destination address. This can
                     * refer to a single IP address, an IP set ('+ipsetname') or
                     * an IP alias definition. You can also specify an address
                     * range like '20.34.101.207-201.3.9.99', or a list of IP
                     * addresses and networks (entries are separated by comma).
                     * Please do not mix IPv4 and IPv6 addresses inside such
                     * lists.
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     * @param dport Restrict TCP/UDP destination port. You can
                     * use service names or simple numbers (0-65535), as defined
                     * in '/etc/services'. Port ranges can be specified with
                     * '\d+:\d+', for example '80:85', and you can use comma
                     * separated list to match several ports or ranges.
                     * @param enable Flag to enable/disable a rule.
                     * @param iface Network interface name. You have to use
                     * network configuration key names for VMs and containers
                     * ('net\d+'). Host related rules can use arbitrary strings.
                     * @param macro Use predefined standard macro.
                     * @param moveto Move rule to new position
                     * &amp;lt;moveto&amp;gt;. Other arguments are ignored.
                     * @param proto IP protocol. You can use protocol names
                     * ('tcp'/'udp') or simple numbers, as defined in
                     * '/etc/protocols'.
                     * @param source Restrict packet source address. This can
                     * refer to a single IP address, an IP set ('+ipsetname') or
                     * an IP alias definition. You can also specify an address
                     * range like '20.34.101.207-201.3.9.99', or a list of IP
                     * addresses and networks (entries are separated by comma).
                     * Please do not mix IPv4 and IPv6 addresses inside such
                     * lists.
                     * @param sport Restrict TCP/UDP source port. You can use
                     * service names or simple numbers (0-65535), as defined in
                     * '/etc/services'. Port ranges can be specified with
                     * '\d+:\d+', for example '80:85', and you can use comma
                     * separated list to match several ports or ranges.
                     * @param type Rule type. Enum: in,out,group
                     */
                    public void updateRule(String action, String comment, String delete, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer moveto, String proto, String source, String sport, String type) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("action", action);
                        parameters.put("comment", comment);
                        parameters.put("delete", delete);
                        parameters.put("dest", dest);
                        parameters.put("digest", digest);
                        parameters.put("dport", dport);
                        parameters.put("enable", enable);
                        parameters.put("iface", iface);
                        parameters.put("macro", macro);
                        parameters.put("moveto", moveto);
                        parameters.put("proto", proto);
                        parameters.put("source", source);
                        parameters.put("sport", sport);
                        parameters.put("type", type);
                        _client.put("/cluster/firewall/rules/" + _pos + "", parameters);
                    }

                    /**
                     * Modify rule data.
                     */
                    public void updateRule() throws JSONException {
                        _client.put("/cluster/firewall/rules/" + _pos + "", null);
                    }
                }

                /**
                 * List rules.
                 */
                public JSONObject getRules() throws JSONException {
                    return _client.get("/cluster/firewall/rules", null);
                }

                /**
                 * Create new rule.
                 *
                 * @param action Rule action ('ACCEPT', 'DROP', 'REJECT') or
                 * security group name.
                 * @param type Rule type. Enum: in,out,group
                 * @param comment Descriptive comment.
                 * @param dest Restrict packet destination address. This can
                 * refer to a single IP address, an IP set ('+ipsetname') or an
                 * IP alias definition. You can also specify an address range
                 * like '20.34.101.207-201.3.9.99', or a list of IP addresses
                 * and networks (entries are separated by comma). Please do not
                 * mix IPv4 and IPv6 addresses inside such lists.
                 * @param digest Prevent changes if current configuration file
                 * has different SHA1 digest. This can be used to prevent
                 * concurrent modifications.
                 * @param dport Restrict TCP/UDP destination port. You can use
                 * service names or simple numbers (0-65535), as defined in
                 * '/etc/services'. Port ranges can be specified with '\d+:\d+',
                 * for example '80:85', and you can use comma separated list to
                 * match several ports or ranges.
                 * @param enable Flag to enable/disable a rule.
                 * @param iface Network interface name. You have to use network
                 * configuration key names for VMs and containers ('net\d+').
                 * Host related rules can use arbitrary strings.
                 * @param macro Use predefined standard macro.
                 * @param pos Update rule at position &amp;lt;pos&amp;gt;.
                 * @param proto IP protocol. You can use protocol names
                 * ('tcp'/'udp') or simple numbers, as defined in
                 * '/etc/protocols'.
                 * @param source Restrict packet source address. This can refer
                 * to a single IP address, an IP set ('+ipsetname') or an IP
                 * alias definition. You can also specify an address range like
                 * '20.34.101.207-201.3.9.99', or a list of IP addresses and
                 * networks (entries are separated by comma). Please do not mix
                 * IPv4 and IPv6 addresses inside such lists.
                 * @param sport Restrict TCP/UDP source port. You can use
                 * service names or simple numbers (0-65535), as defined in
                 * '/etc/services'. Port ranges can be specified with '\d+:\d+',
                 * for example '80:85', and you can use comma separated list to
                 * match several ports or ranges.
                 */
                public void createRule(String action, String type, String comment, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer pos, String proto, String source, String sport) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("action", action);
                    parameters.put("type", type);
                    parameters.put("comment", comment);
                    parameters.put("dest", dest);
                    parameters.put("digest", digest);
                    parameters.put("dport", dport);
                    parameters.put("enable", enable);
                    parameters.put("iface", iface);
                    parameters.put("macro", macro);
                    parameters.put("pos", pos);
                    parameters.put("proto", proto);
                    parameters.put("source", source);
                    parameters.put("sport", sport);
                    _client.post("/cluster/firewall/rules", parameters);
                }

                /**
                 * Create new rule.
                 *
                 * @param action Rule action ('ACCEPT', 'DROP', 'REJECT') or
                 * security group name.
                 * @param type Rule type. Enum: in,out,group
                 */
                public void createRule(String action, String type) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("action", action);
                    parameters.put("type", type);
                    _client.post("/cluster/firewall/rules", parameters);
                }
            }

            public class PVEIpset extends Base {

                protected PVEIpset(Client client) {
                    _client = client;
                }

                public PVEItemName get(Object name) {
                    return new PVEItemName(_client, name);
                }

                public class PVEItemName extends Base {

                    private Object _name;

                    protected PVEItemName(Client client, Object name) {
                        _client = client;
                        _name = name;
                    }

                    public PVEItemCidr get(Object cidr) {
                        return new PVEItemCidr(_client, _name, cidr);
                    }

                    public class PVEItemCidr extends Base {

                        private Object _name;
                        private Object _cidr;

                        protected PVEItemCidr(Client client, Object name, Object cidr) {
                            _client = client;
                            _name = name;
                            _cidr = cidr;
                        }

                        /**
                         * Remove IP or Network from IPSet.
                         *
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         */
                        public void removeIp(String digest) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("digest", digest);
                            _client.delete("/cluster/firewall/ipset/" + _name + "/" + _cidr + "", parameters);
                        }

                        /**
                         * Remove IP or Network from IPSet.
                         */
                        public void removeIp() throws JSONException {
                            _client.delete("/cluster/firewall/ipset/" + _name + "/" + _cidr + "", null);
                        }

                        /**
                         * Read IP or Network settings from IPSet.
                         */
                        public JSONObject readIp() throws JSONException {
                            return _client.get("/cluster/firewall/ipset/" + _name + "/" + _cidr + "", null);
                        }

                        /**
                         * Update IP or Network settings
                         *
                         * @param comment
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         * @param nomatch
                         */
                        public void updateIp(String comment, String digest, Boolean nomatch) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("comment", comment);
                            parameters.put("digest", digest);
                            parameters.put("nomatch", nomatch);
                            _client.put("/cluster/firewall/ipset/" + _name + "/" + _cidr + "", parameters);
                        }

                        /**
                         * Update IP or Network settings
                         */
                        public void updateIp() throws JSONException {
                            _client.put("/cluster/firewall/ipset/" + _name + "/" + _cidr + "", null);
                        }
                    }

                    /**
                     * Delete IPSet
                     */
                    public void deleteIpset() throws JSONException {
                        _client.delete("/cluster/firewall/ipset/" + _name + "", null);
                    }

                    /**
                     * List IPSet content
                     */
                    public JSONObject getIpset() throws JSONException {
                        return _client.get("/cluster/firewall/ipset/" + _name + "", null);
                    }

                    /**
                     * Add IP or Network to IPSet.
                     *
                     * @param cidr Network/IP specification in CIDR format.
                     * @param comment
                     * @param nomatch
                     */
                    public void createIp(String cidr, String comment, Boolean nomatch) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("cidr", cidr);
                        parameters.put("comment", comment);
                        parameters.put("nomatch", nomatch);
                        _client.post("/cluster/firewall/ipset/" + _name + "", parameters);
                    }

                    /**
                     * Add IP or Network to IPSet.
                     *
                     * @param cidr Network/IP specification in CIDR format.
                     */
                    public void createIp(String cidr) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("cidr", cidr);
                        _client.post("/cluster/firewall/ipset/" + _name + "", parameters);
                    }
                }

                /**
                 * List IPSets
                 */
                public JSONObject ipsetIndex() throws JSONException {
                    return _client.get("/cluster/firewall/ipset", null);
                }

                /**
                 * Create new IPSet
                 *
                 * @param name IP set name.
                 * @param comment
                 * @param digest Prevent changes if current configuration file
                 * has different SHA1 digest. This can be used to prevent
                 * concurrent modifications.
                 * @param rename Rename an existing IPSet. You can set 'rename'
                 * to the same value as 'name' to update the 'comment' of an
                 * existing IPSet.
                 */
                public void createIpset(String name, String comment, String digest, String rename) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("name", name);
                    parameters.put("comment", comment);
                    parameters.put("digest", digest);
                    parameters.put("rename", rename);
                    _client.post("/cluster/firewall/ipset", parameters);
                }

                /**
                 * Create new IPSet
                 *
                 * @param name IP set name.
                 */
                public void createIpset(String name) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("name", name);
                    _client.post("/cluster/firewall/ipset", parameters);
                }
            }

            public class PVEAliases extends Base {

                protected PVEAliases(Client client) {
                    _client = client;
                }

                public PVEItemName get(Object name) {
                    return new PVEItemName(_client, name);
                }

                public class PVEItemName extends Base {

                    private Object _name;

                    protected PVEItemName(Client client, Object name) {
                        _client = client;
                        _name = name;
                    }

                    /**
                     * Remove IP or Network alias.
                     *
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     */
                    public void removeAlias(String digest) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("digest", digest);
                        _client.delete("/cluster/firewall/aliases/" + _name + "", parameters);
                    }

                    /**
                     * Remove IP or Network alias.
                     */
                    public void removeAlias() throws JSONException {
                        _client.delete("/cluster/firewall/aliases/" + _name + "", null);
                    }

                    /**
                     * Read alias.
                     */
                    public JSONObject readAlias() throws JSONException {
                        return _client.get("/cluster/firewall/aliases/" + _name + "", null);
                    }

                    /**
                     * Update IP or Network alias.
                     *
                     * @param cidr Network/IP specification in CIDR format.
                     * @param comment
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     * @param rename Rename an existing alias.
                     */
                    public void updateAlias(String cidr, String comment, String digest, String rename) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("cidr", cidr);
                        parameters.put("comment", comment);
                        parameters.put("digest", digest);
                        parameters.put("rename", rename);
                        _client.put("/cluster/firewall/aliases/" + _name + "", parameters);
                    }

                    /**
                     * Update IP or Network alias.
                     *
                     * @param cidr Network/IP specification in CIDR format.
                     */
                    public void updateAlias(String cidr) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("cidr", cidr);
                        _client.put("/cluster/firewall/aliases/" + _name + "", parameters);
                    }
                }

                /**
                 * List aliases
                 */
                public JSONObject getAliases() throws JSONException {
                    return _client.get("/cluster/firewall/aliases", null);
                }

                /**
                 * Create IP or Network Alias.
                 *
                 * @param cidr Network/IP specification in CIDR format.
                 * @param name Alias name.
                 * @param comment
                 */
                public void createAlias(String cidr, String name, String comment) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("cidr", cidr);
                    parameters.put("name", name);
                    parameters.put("comment", comment);
                    _client.post("/cluster/firewall/aliases", parameters);
                }

                /**
                 * Create IP or Network Alias.
                 *
                 * @param cidr Network/IP specification in CIDR format.
                 * @param name Alias name.
                 */
                public void createAlias(String cidr, String name) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("cidr", cidr);
                    parameters.put("name", name);
                    _client.post("/cluster/firewall/aliases", parameters);
                }
            }

            public class PVEOptions extends Base {

                protected PVEOptions(Client client) {
                    _client = client;
                }

                /**
                 * Get Firewall options.
                 */
                public JSONObject getOptions() throws JSONException {
                    return _client.get("/cluster/firewall/options", null);
                }

                /**
                 * Set Firewall options.
                 *
                 * @param delete A list of settings you want to delete.
                 * @param digest Prevent changes if current configuration file
                 * has different SHA1 digest. This can be used to prevent
                 * concurrent modifications.
                 * @param enable Enable or disable the firewall cluster wide.
                 * @param policy_in Input policy. Enum: ACCEPT,REJECT,DROP
                 * @param policy_out Output policy. Enum: ACCEPT,REJECT,DROP
                 */
                public void setOptions(String delete, String digest, Integer enable, String policy_in, String policy_out) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("delete", delete);
                    parameters.put("digest", digest);
                    parameters.put("enable", enable);
                    parameters.put("policy_in", policy_in);
                    parameters.put("policy_out", policy_out);
                    _client.put("/cluster/firewall/options", parameters);
                }

                /**
                 * Set Firewall options.
                 */
                public void setOptions() throws JSONException {
                    _client.put("/cluster/firewall/options", null);
                }
            }

            public class PVEMacros extends Base {

                protected PVEMacros(Client client) {
                    _client = client;
                }

                /**
                 * List available macros
                 */
                public JSONObject getMacros() throws JSONException {
                    return _client.get("/cluster/firewall/macros", null);
                }
            }

            public class PVERefs extends Base {

                protected PVERefs(Client client) {
                    _client = client;
                }

                /**
                 * Lists possible IPSet/Alias reference which are allowed in
                 * source/dest properties.
                 *
                 * @param type Only list references of specified type. Enum:
                 * alias,ipset
                 */
                public JSONObject refs(String type) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("type", type);
                    return _client.get("/cluster/firewall/refs", parameters);
                }

                /**
                 * Lists possible IPSet/Alias reference which are allowed in
                 * source/dest properties.
                 */
                public JSONObject refs() throws JSONException {
                    return _client.get("/cluster/firewall/refs", null);
                }
            }

            /**
             * Directory index.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/cluster/firewall", null);
            }
        }

        public class PVEBackup extends Base {

            protected PVEBackup(Client client) {
                _client = client;
            }

            public PVEItemId get(Object id) {
                return new PVEItemId(_client, id);
            }

            public class PVEItemId extends Base {

                private Object _id;

                protected PVEItemId(Client client, Object id) {
                    _client = client;
                    _id = id;
                }

                /**
                 * Delete vzdump backup job definition.
                 */
                public void deleteJob() throws JSONException {
                    _client.delete("/cluster/backup/" + _id + "", null);
                }

                /**
                 * Read vzdump backup job definition.
                 */
                public JSONObject readJob() throws JSONException {
                    return _client.get("/cluster/backup/" + _id + "", null);
                }

                /**
                 * Update vzdump backup job definition.
                 *
                 * @param starttime Job Start time.
                 * @param all Backup all known guest systems on this host.
                 * @param bwlimit Limit I/O bandwidth (KBytes per second).
                 * @param compress Compress dump file. Enum: 0,1,gzip,lzo
                 * @param delete A list of settings you want to delete.
                 * @param dow Day of week selection.
                 * @param dumpdir Store resulting files to specified directory.
                 * @param enabled Enable or disable the job.
                 * @param exclude Exclude specified guest systems (assumes
                 * --all)
                 * @param exclude_path Exclude certain files/directories (shell
                 * globs).
                 * @param ionice Set CFQ ionice priority.
                 * @param lockwait Maximal time to wait for the global lock
                 * (minutes).
                 * @param mailnotification Specify when to send an email Enum:
                 * always,failure
                 * @param mailto Comma-separated list of email addresses that
                 * should receive email notifications.
                 * @param maxfiles Maximal number of backup files per guest
                 * system.
                 * @param mode Backup mode. Enum: snapshot,suspend,stop
                 * @param node Only run if executed on this node.
                 * @param pigz Use pigz instead of gzip when N&amp;gt;0. N=1
                 * uses half of cores, N&amp;gt;1 uses N as thread count.
                 * @param quiet Be quiet.
                 * @param remove Remove old backup files if there are more than
                 * 'maxfiles' backup files.
                 * @param script Use specified hook script.
                 * @param size Unused, will be removed in a future release.
                 * @param stdexcludes Exclude temporary files and logs.
                 * @param stop Stop runnig backup jobs on this host.
                 * @param stopwait Maximal time to wait until a guest system is
                 * stopped (minutes).
                 * @param storage Store resulting file to this storage.
                 * @param tmpdir Store temporary files to specified directory.
                 * @param vmid The ID of the guest system you want to backup.
                 */
                public void updateJob(String starttime, Boolean all, Integer bwlimit, String compress, String delete, String dow, String dumpdir, Boolean enabled, String exclude, String exclude_path, Integer ionice, Integer lockwait, String mailnotification, String mailto, Integer maxfiles, String mode, String node, Integer pigz, Boolean quiet, Boolean remove, String script, Integer size, Boolean stdexcludes, Boolean stop, Integer stopwait, String storage, String tmpdir, String vmid) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("starttime", starttime);
                    parameters.put("all", all);
                    parameters.put("bwlimit", bwlimit);
                    parameters.put("compress", compress);
                    parameters.put("delete", delete);
                    parameters.put("dow", dow);
                    parameters.put("dumpdir", dumpdir);
                    parameters.put("enabled", enabled);
                    parameters.put("exclude", exclude);
                    parameters.put("exclude-path", exclude_path);
                    parameters.put("ionice", ionice);
                    parameters.put("lockwait", lockwait);
                    parameters.put("mailnotification", mailnotification);
                    parameters.put("mailto", mailto);
                    parameters.put("maxfiles", maxfiles);
                    parameters.put("mode", mode);
                    parameters.put("node", node);
                    parameters.put("pigz", pigz);
                    parameters.put("quiet", quiet);
                    parameters.put("remove", remove);
                    parameters.put("script", script);
                    parameters.put("size", size);
                    parameters.put("stdexcludes", stdexcludes);
                    parameters.put("stop", stop);
                    parameters.put("stopwait", stopwait);
                    parameters.put("storage", storage);
                    parameters.put("tmpdir", tmpdir);
                    parameters.put("vmid", vmid);
                    _client.put("/cluster/backup/" + _id + "", parameters);
                }

                /**
                 * Update vzdump backup job definition.
                 *
                 * @param starttime Job Start time.
                 */
                public void updateJob(String starttime) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("starttime", starttime);
                    _client.put("/cluster/backup/" + _id + "", parameters);
                }
            }

            /**
             * List vzdump backup schedule.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/cluster/backup", null);
            }

            /**
             * Create new vzdump backup job.
             *
             * @param starttime Job Start time.
             * @param all Backup all known guest systems on this host.
             * @param bwlimit Limit I/O bandwidth (KBytes per second).
             * @param compress Compress dump file. Enum: 0,1,gzip,lzo
             * @param dow Day of week selection.
             * @param dumpdir Store resulting files to specified directory.
             * @param enabled Enable or disable the job.
             * @param exclude Exclude specified guest systems (assumes --all)
             * @param exclude_path Exclude certain files/directories (shell
             * globs).
             * @param ionice Set CFQ ionice priority.
             * @param lockwait Maximal time to wait for the global lock
             * (minutes).
             * @param mailnotification Specify when to send an email Enum:
             * always,failure
             * @param mailto Comma-separated list of email addresses that should
             * receive email notifications.
             * @param maxfiles Maximal number of backup files per guest system.
             * @param mode Backup mode. Enum: snapshot,suspend,stop
             * @param node Only run if executed on this node.
             * @param pigz Use pigz instead of gzip when N&amp;gt;0. N=1 uses
             * half of cores, N&amp;gt;1 uses N as thread count.
             * @param quiet Be quiet.
             * @param remove Remove old backup files if there are more than
             * 'maxfiles' backup files.
             * @param script Use specified hook script.
             * @param size Unused, will be removed in a future release.
             * @param stdexcludes Exclude temporary files and logs.
             * @param stop Stop runnig backup jobs on this host.
             * @param stopwait Maximal time to wait until a guest system is
             * stopped (minutes).
             * @param storage Store resulting file to this storage.
             * @param tmpdir Store temporary files to specified directory.
             * @param vmid The ID of the guest system you want to backup.
             */
            public void createJob(String starttime, Boolean all, Integer bwlimit, String compress, String dow, String dumpdir, Boolean enabled, String exclude, String exclude_path, Integer ionice, Integer lockwait, String mailnotification, String mailto, Integer maxfiles, String mode, String node, Integer pigz, Boolean quiet, Boolean remove, String script, Integer size, Boolean stdexcludes, Boolean stop, Integer stopwait, String storage, String tmpdir, String vmid) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("starttime", starttime);
                parameters.put("all", all);
                parameters.put("bwlimit", bwlimit);
                parameters.put("compress", compress);
                parameters.put("dow", dow);
                parameters.put("dumpdir", dumpdir);
                parameters.put("enabled", enabled);
                parameters.put("exclude", exclude);
                parameters.put("exclude-path", exclude_path);
                parameters.put("ionice", ionice);
                parameters.put("lockwait", lockwait);
                parameters.put("mailnotification", mailnotification);
                parameters.put("mailto", mailto);
                parameters.put("maxfiles", maxfiles);
                parameters.put("mode", mode);
                parameters.put("node", node);
                parameters.put("pigz", pigz);
                parameters.put("quiet", quiet);
                parameters.put("remove", remove);
                parameters.put("script", script);
                parameters.put("size", size);
                parameters.put("stdexcludes", stdexcludes);
                parameters.put("stop", stop);
                parameters.put("stopwait", stopwait);
                parameters.put("storage", storage);
                parameters.put("tmpdir", tmpdir);
                parameters.put("vmid", vmid);
                _client.post("/cluster/backup", parameters);
            }

            /**
             * Create new vzdump backup job.
             *
             * @param starttime Job Start time.
             */
            public void createJob(String starttime) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("starttime", starttime);
                _client.post("/cluster/backup", parameters);
            }
        }

        public class PVEHa extends Base {

            protected PVEHa(Client client) {
                _client = client;
            }
            private PVEResources _resources;

            public PVEResources getResources() {
                if (_resources == null) {
                    _resources = new PVEResources(_client);
                }
                return _resources;
            }
            private PVEGroups _groups;

            public PVEGroups getGroups() {
                if (_groups == null) {
                    _groups = new PVEGroups(_client);
                }
                return _groups;
            }
            private PVEStatus _status;

            public PVEStatus getStatus() {
                if (_status == null) {
                    _status = new PVEStatus(_client);
                }
                return _status;
            }

            public class PVEResources extends Base {

                protected PVEResources(Client client) {
                    _client = client;
                }

                public PVEItemSid get(Object sid) {
                    return new PVEItemSid(_client, sid);
                }

                public class PVEItemSid extends Base {

                    private Object _sid;

                    protected PVEItemSid(Client client, Object sid) {
                        _client = client;
                        _sid = sid;
                    }
                    private PVEMigrate _migrate;

                    public PVEMigrate getMigrate() {
                        if (_migrate == null) {
                            _migrate = new PVEMigrate(_client, _sid);
                        }
                        return _migrate;
                    }
                    private PVERelocate _relocate;

                    public PVERelocate getRelocate() {
                        if (_relocate == null) {
                            _relocate = new PVERelocate(_client, _sid);
                        }
                        return _relocate;
                    }

                    public class PVEMigrate extends Base {

                        private Object _sid;

                        protected PVEMigrate(Client client, Object sid) {
                            _client = client;
                            _sid = sid;
                        }

                        /**
                         * Request resource migration (online) to another node.
                         *
                         * @param node The cluster node name.
                         */
                        public void migrate(String node) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("node", node);
                            _client.post("/cluster/ha/resources/" + _sid + "/migrate", parameters);
                        }
                    }

                    public class PVERelocate extends Base {

                        private Object _sid;

                        protected PVERelocate(Client client, Object sid) {
                            _client = client;
                            _sid = sid;
                        }

                        /**
                         * Request resource relocatzion to another node. This
                         * stops the service on the old node, and restarts it on
                         * the target node.
                         *
                         * @param node The cluster node name.
                         */
                        public void relocate(String node) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("node", node);
                            _client.post("/cluster/ha/resources/" + _sid + "/relocate", parameters);
                        }
                    }

                    /**
                     * Delete resource configuration.
                     */
                    public void delete() throws JSONException {
                        _client.delete("/cluster/ha/resources/" + _sid + "", null);
                    }

                    /**
                     * Read resource configuration.
                     */
                    public JSONObject read() throws JSONException {
                        return _client.get("/cluster/ha/resources/" + _sid + "", null);
                    }

                    /**
                     * Update resource configuration.
                     *
                     * @param comment Description.
                     * @param delete A list of settings you want to delete.
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     * @param group The HA group identifier.
                     * @param max_relocate Maximal number of service relocate
                     * tries when a service failes to start.
                     * @param max_restart Maximal number of tries to restart the
                     * service on a node after its start failed.
                     * @param state Requested resource state. Enum:
                     * started,stopped,enabled,disabled
                     */
                    public void update(String comment, String delete, String digest, String group, Integer max_relocate, Integer max_restart, String state) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("comment", comment);
                        parameters.put("delete", delete);
                        parameters.put("digest", digest);
                        parameters.put("group", group);
                        parameters.put("max_relocate", max_relocate);
                        parameters.put("max_restart", max_restart);
                        parameters.put("state", state);
                        _client.put("/cluster/ha/resources/" + _sid + "", parameters);
                    }

                    /**
                     * Update resource configuration.
                     */
                    public void update() throws JSONException {
                        _client.put("/cluster/ha/resources/" + _sid + "", null);
                    }
                }

                /**
                 * List HA resources.
                 *
                 * @param type Only list resources of specific type Enum: ct,vm
                 */
                public JSONObject index(String type) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("type", type);
                    return _client.get("/cluster/ha/resources", parameters);
                }

                /**
                 * List HA resources.
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/cluster/ha/resources", null);
                }

                /**
                 * Create a new HA resource.
                 *
                 * @param sid HA resource ID. This consists of a resource type
                 * followed by a resource specific name, separated with colon
                 * (example: vm:100 / ct:100). For virtual machines and
                 * containers, you can simply use the VM or CT id as a shortcut
                 * (example: 100).
                 * @param comment Description.
                 * @param group The HA group identifier.
                 * @param max_relocate Maximal number of service relocate tries
                 * when a service failes to start.
                 * @param max_restart Maximal number of tries to restart the
                 * service on a node after its start failed.
                 * @param state Requested resource state. Enum:
                 * started,stopped,enabled,disabled
                 * @param type Resource type. Enum: ct,vm
                 */
                public void create(String sid, String comment, String group, Integer max_relocate, Integer max_restart, String state, String type) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("sid", sid);
                    parameters.put("comment", comment);
                    parameters.put("group", group);
                    parameters.put("max_relocate", max_relocate);
                    parameters.put("max_restart", max_restart);
                    parameters.put("state", state);
                    parameters.put("type", type);
                    _client.post("/cluster/ha/resources", parameters);
                }

                /**
                 * Create a new HA resource.
                 *
                 * @param sid HA resource ID. This consists of a resource type
                 * followed by a resource specific name, separated with colon
                 * (example: vm:100 / ct:100). For virtual machines and
                 * containers, you can simply use the VM or CT id as a shortcut
                 * (example: 100).
                 */
                public void create(String sid) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("sid", sid);
                    _client.post("/cluster/ha/resources", parameters);
                }
            }

            public class PVEGroups extends Base {

                protected PVEGroups(Client client) {
                    _client = client;
                }

                public PVEItemGroup get(Object group) {
                    return new PVEItemGroup(_client, group);
                }

                public class PVEItemGroup extends Base {

                    private Object _group;

                    protected PVEItemGroup(Client client, Object group) {
                        _client = client;
                        _group = group;
                    }

                    /**
                     * Delete ha group configuration.
                     */
                    public void delete() throws JSONException {
                        _client.delete("/cluster/ha/groups/" + _group + "", null);
                    }

                    /**
                     * Read ha group configuration.
                     */
                    public JSONObject read() throws JSONException {
                        return _client.get("/cluster/ha/groups/" + _group + "", null);
                    }

                    /**
                     * Update ha group configuration.
                     *
                     * @param comment Description.
                     * @param delete A list of settings you want to delete.
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     * @param nodes List of cluster node names with optional
                     * priority.
                     * @param nofailback The CRM tries to run services on the
                     * node with the highest priority. If a node with higher
                     * priority comes online, the CRM migrates the service to
                     * that node. Enabling nofailback prevents that behavior.
                     * @param restricted Resources bound to restricted groups
                     * may only run on nodes defined by the group.
                     */
                    public void update(String comment, String delete, String digest, String nodes, Boolean nofailback, Boolean restricted) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("comment", comment);
                        parameters.put("delete", delete);
                        parameters.put("digest", digest);
                        parameters.put("nodes", nodes);
                        parameters.put("nofailback", nofailback);
                        parameters.put("restricted", restricted);
                        _client.put("/cluster/ha/groups/" + _group + "", parameters);
                    }

                    /**
                     * Update ha group configuration.
                     */
                    public void update() throws JSONException {
                        _client.put("/cluster/ha/groups/" + _group + "", null);
                    }
                }

                /**
                 * Get HA groups.
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/cluster/ha/groups", null);
                }

                /**
                 * Create a new HA group.
                 *
                 * @param group The HA group identifier.
                 * @param nodes List of cluster node names with optional
                 * priority.
                 * @param comment Description.
                 * @param nofailback The CRM tries to run services on the node
                 * with the highest priority. If a node with higher priority
                 * comes online, the CRM migrates the service to that node.
                 * Enabling nofailback prevents that behavior.
                 * @param restricted Resources bound to restricted groups may
                 * only run on nodes defined by the group.
                 * @param type Group type. Enum: group
                 */
                public void create(String group, String nodes, String comment, Boolean nofailback, Boolean restricted, String type) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("group", group);
                    parameters.put("nodes", nodes);
                    parameters.put("comment", comment);
                    parameters.put("nofailback", nofailback);
                    parameters.put("restricted", restricted);
                    parameters.put("type", type);
                    _client.post("/cluster/ha/groups", parameters);
                }

                /**
                 * Create a new HA group.
                 *
                 * @param group The HA group identifier.
                 * @param nodes List of cluster node names with optional
                 * priority.
                 */
                public void create(String group, String nodes) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("group", group);
                    parameters.put("nodes", nodes);
                    _client.post("/cluster/ha/groups", parameters);
                }
            }

            public class PVEStatus extends Base {

                protected PVEStatus(Client client) {
                    _client = client;
                }
                private PVECurrent _current;

                public PVECurrent getCurrent() {
                    if (_current == null) {
                        _current = new PVECurrent(_client);
                    }
                    return _current;
                }
                private PVEManagerStatus _managerStatus;

                public PVEManagerStatus getManagerStatus() {
                    if (_managerStatus == null) {
                        _managerStatus = new PVEManagerStatus(_client);
                    }
                    return _managerStatus;
                }

                public class PVECurrent extends Base {

                    protected PVECurrent(Client client) {
                        _client = client;
                    }

                    /**
                     * Get HA manger status.
                     */
                    public JSONObject status() throws JSONException {
                        return _client.get("/cluster/ha/status/current", null);
                    }
                }

                public class PVEManagerStatus extends Base {

                    protected PVEManagerStatus(Client client) {
                        _client = client;
                    }

                    /**
                     * Get full HA manger status, including LRM status.
                     */
                    public JSONObject managerStatus() throws JSONException {
                        return _client.get("/cluster/ha/status/manager_status", null);
                    }
                }

                /**
                 * Directory index.
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/cluster/ha/status", null);
                }
            }

            /**
             * Directory index.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/cluster/ha", null);
            }
        }

        public class PVELog extends Base {

            protected PVELog(Client client) {
                _client = client;
            }

            /**
             * Read cluster log
             *
             * @param max Maximum number of entries.
             */
            public JSONObject log(Integer max) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("max", max);
                return _client.get("/cluster/log", parameters);
            }

            /**
             * Read cluster log
             */
            public JSONObject log() throws JSONException {
                return _client.get("/cluster/log", null);
            }
        }

        public class PVEResources extends Base {

            protected PVEResources(Client client) {
                _client = client;
            }

            /**
             * Resources index (cluster wide).
             *
             * @param type Enum: vm,storage,node
             */
            public JSONObject resources(String type) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("type", type);
                return _client.get("/cluster/resources", parameters);
            }

            /**
             * Resources index (cluster wide).
             */
            public JSONObject resources() throws JSONException {
                return _client.get("/cluster/resources", null);
            }
        }

        public class PVETasks extends Base {

            protected PVETasks(Client client) {
                _client = client;
            }

            /**
             * List recent tasks (cluster wide).
             */
            public JSONObject tasks() throws JSONException {
                return _client.get("/cluster/tasks", null);
            }
        }

        public class PVEOptions extends Base {

            protected PVEOptions(Client client) {
                _client = client;
            }

            /**
             * Get datacenter options.
             */
            public JSONObject getOptions() throws JSONException {
                return _client.get("/cluster/options", null);
            }

            /**
             * Set datacenter options.
             *
             * @param console Select the default Console viewer. You can either
             * use the builtin java applet (VNC), an external virt-viewer
             * comtatible application (SPICE), or an HTML5 based viewer (noVNC).
             * Enum: applet,vv,html5
             * @param delete A list of settings you want to delete.
             * @param email_from Specify email address to send notification from
             * (default is root@$hostname)
             * @param fencing Set the fencing mode of the HA cluster. Hardware
             * mode needs a valid configuration of fence devices in
             * /etc/pve/ha/fence.cfg. With both all two modes are used. WARNING:
             * 'hardware' and 'both' are EXPERIMENTAL &amp; WIP Enum:
             * watchdog,hardware,both
             * @param http_proxy Specify external http proxy which is used for
             * downloads (example: 'http://username:password@host:port/')
             * @param keyboard Default keybord layout for vnc server. Enum:
             * de,de-ch,da,en-gb,en-us,es,fi,fr,fr-be,fr-ca,fr-ch,hu,is,it,ja,lt,mk,nl,no,pl,pt,pt-br,sv,sl,tr
             * @param language Default GUI language. Enum: en,de
             * @param mac_prefix Prefix for autogenerated MAC addresses.
             * @param max_workers Defines how many workers (per node) are
             * maximal started on actions like 'stopall VMs' or task from the
             * ha-manager.
             * @param migration For cluster wide migration settings.
             * @param migration_unsecure Migration is secure using SSH tunnel by
             * default. For secure private networks you can disable it to speed
             * up migration. Deprecated, use the 'migration' property instead!
             */
            public void setOptions(String console, String delete, String email_from, String fencing, String http_proxy, String keyboard, String language, String mac_prefix, Integer max_workers, String migration, Boolean migration_unsecure) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("console", console);
                parameters.put("delete", delete);
                parameters.put("email_from", email_from);
                parameters.put("fencing", fencing);
                parameters.put("http_proxy", http_proxy);
                parameters.put("keyboard", keyboard);
                parameters.put("language", language);
                parameters.put("mac_prefix", mac_prefix);
                parameters.put("max_workers", max_workers);
                parameters.put("migration", migration);
                parameters.put("migration_unsecure", migration_unsecure);
                _client.put("/cluster/options", parameters);
            }

            /**
             * Set datacenter options.
             */
            public void setOptions() throws JSONException {
                _client.put("/cluster/options", null);
            }
        }

        public class PVEStatus extends Base {

            protected PVEStatus(Client client) {
                _client = client;
            }

            /**
             * Get cluster status informations.
             */
            public JSONObject getStatus() throws JSONException {
                return _client.get("/cluster/status", null);
            }
        }

        public class PVENextid extends Base {

            protected PVENextid(Client client) {
                _client = client;
            }

            /**
             * Get next free VMID. If you pass an VMID it will raise an error if
             * the ID is already used.
             *
             * @param vmid The (unique) ID of the VM.
             */
            public JSONObject nextid(Integer vmid) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("vmid", vmid);
                return _client.get("/cluster/nextid", parameters);
            }

            /**
             * Get next free VMID. If you pass an VMID it will raise an error if
             * the ID is already used.
             */
            public JSONObject nextid() throws JSONException {
                return _client.get("/cluster/nextid", null);
            }
        }

        /**
         * Cluster index.
         */
        public JSONObject index() throws JSONException {
            return _client.get("/cluster", null);
        }
    }

    public class PVENodes extends Base {

        protected PVENodes(Client client) {
            _client = client;
        }

        public PVEItemNode get(Object node) {
            return new PVEItemNode(_client, node);
        }

        public class PVEItemNode extends Base {

            private Object _node;

            protected PVEItemNode(Client client, Object node) {
                _client = client;
                _node = node;
            }
            private PVEQemu _qemu;

            public PVEQemu getQemu() {
                if (_qemu == null) {
                    _qemu = new PVEQemu(_client, _node);
                }
                return _qemu;
            }
            private PVELxc _lxc;

            public PVELxc getLxc() {
                if (_lxc == null) {
                    _lxc = new PVELxc(_client, _node);
                }
                return _lxc;
            }
            private PVECeph _ceph;

            public PVECeph getCeph() {
                if (_ceph == null) {
                    _ceph = new PVECeph(_client, _node);
                }
                return _ceph;
            }
            private PVEVzdump _vzdump;

            public PVEVzdump getVzdump() {
                if (_vzdump == null) {
                    _vzdump = new PVEVzdump(_client, _node);
                }
                return _vzdump;
            }
            private PVEServices _services;

            public PVEServices getServices() {
                if (_services == null) {
                    _services = new PVEServices(_client, _node);
                }
                return _services;
            }
            private PVESubscription _subscription;

            public PVESubscription getSubscription() {
                if (_subscription == null) {
                    _subscription = new PVESubscription(_client, _node);
                }
                return _subscription;
            }
            private PVENetwork _network;

            public PVENetwork getNetwork() {
                if (_network == null) {
                    _network = new PVENetwork(_client, _node);
                }
                return _network;
            }
            private PVETasks _tasks;

            public PVETasks getTasks() {
                if (_tasks == null) {
                    _tasks = new PVETasks(_client, _node);
                }
                return _tasks;
            }
            private PVEScan _scan;

            public PVEScan getScan() {
                if (_scan == null) {
                    _scan = new PVEScan(_client, _node);
                }
                return _scan;
            }
            private PVEStorage _storage;

            public PVEStorage getStorage() {
                if (_storage == null) {
                    _storage = new PVEStorage(_client, _node);
                }
                return _storage;
            }
            private PVEDisks _disks;

            public PVEDisks getDisks() {
                if (_disks == null) {
                    _disks = new PVEDisks(_client, _node);
                }
                return _disks;
            }
            private PVEApt _apt;

            public PVEApt getApt() {
                if (_apt == null) {
                    _apt = new PVEApt(_client, _node);
                }
                return _apt;
            }
            private PVEFirewall _firewall;

            public PVEFirewall getFirewall() {
                if (_firewall == null) {
                    _firewall = new PVEFirewall(_client, _node);
                }
                return _firewall;
            }
            private PVEReplication _replication;

            public PVEReplication getReplication() {
                if (_replication == null) {
                    _replication = new PVEReplication(_client, _node);
                }
                return _replication;
            }
            private PVEVersion _version;

            public PVEVersion getVersion() {
                if (_version == null) {
                    _version = new PVEVersion(_client, _node);
                }
                return _version;
            }
            private PVEStatus _status;

            public PVEStatus getStatus() {
                if (_status == null) {
                    _status = new PVEStatus(_client, _node);
                }
                return _status;
            }
            private PVENetstat _netstat;

            public PVENetstat getNetstat() {
                if (_netstat == null) {
                    _netstat = new PVENetstat(_client, _node);
                }
                return _netstat;
            }
            private PVEExecute _execute;

            public PVEExecute getExecute() {
                if (_execute == null) {
                    _execute = new PVEExecute(_client, _node);
                }
                return _execute;
            }
            private PVERrd _rrd;

            public PVERrd getRrd() {
                if (_rrd == null) {
                    _rrd = new PVERrd(_client, _node);
                }
                return _rrd;
            }
            private PVERrddata _rrddata;

            public PVERrddata getRrddata() {
                if (_rrddata == null) {
                    _rrddata = new PVERrddata(_client, _node);
                }
                return _rrddata;
            }
            private PVESyslog _syslog;

            public PVESyslog getSyslog() {
                if (_syslog == null) {
                    _syslog = new PVESyslog(_client, _node);
                }
                return _syslog;
            }
            private PVEVncshell _vncshell;

            public PVEVncshell getVncshell() {
                if (_vncshell == null) {
                    _vncshell = new PVEVncshell(_client, _node);
                }
                return _vncshell;
            }
            private PVEVncwebsocket _vncwebsocket;

            public PVEVncwebsocket getVncwebsocket() {
                if (_vncwebsocket == null) {
                    _vncwebsocket = new PVEVncwebsocket(_client, _node);
                }
                return _vncwebsocket;
            }
            private PVESpiceshell _spiceshell;

            public PVESpiceshell getSpiceshell() {
                if (_spiceshell == null) {
                    _spiceshell = new PVESpiceshell(_client, _node);
                }
                return _spiceshell;
            }
            private PVEDns _dns;

            public PVEDns getDns() {
                if (_dns == null) {
                    _dns = new PVEDns(_client, _node);
                }
                return _dns;
            }
            private PVETime _time;

            public PVETime getTime() {
                if (_time == null) {
                    _time = new PVETime(_client, _node);
                }
                return _time;
            }
            private PVEAplinfo _aplinfo;

            public PVEAplinfo getAplinfo() {
                if (_aplinfo == null) {
                    _aplinfo = new PVEAplinfo(_client, _node);
                }
                return _aplinfo;
            }
            private PVEReport _report;

            public PVEReport getReport() {
                if (_report == null) {
                    _report = new PVEReport(_client, _node);
                }
                return _report;
            }
            private PVEStartall _startall;

            public PVEStartall getStartall() {
                if (_startall == null) {
                    _startall = new PVEStartall(_client, _node);
                }
                return _startall;
            }
            private PVEStopall _stopall;

            public PVEStopall getStopall() {
                if (_stopall == null) {
                    _stopall = new PVEStopall(_client, _node);
                }
                return _stopall;
            }
            private PVEMigrateall _migrateall;

            public PVEMigrateall getMigrateall() {
                if (_migrateall == null) {
                    _migrateall = new PVEMigrateall(_client, _node);
                }
                return _migrateall;
            }

            public class PVEQemu extends Base {

                private Object _node;

                protected PVEQemu(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                public PVEItemVmid get(Object vmid) {
                    return new PVEItemVmid(_client, _node, vmid);
                }

                public class PVEItemVmid extends Base {

                    private Object _node;
                    private Object _vmid;

                    protected PVEItemVmid(Client client, Object node, Object vmid) {
                        _client = client;
                        _node = node;
                        _vmid = vmid;
                    }
                    private PVEFirewall _firewall;

                    public PVEFirewall getFirewall() {
                        if (_firewall == null) {
                            _firewall = new PVEFirewall(_client, _node, _vmid);
                        }
                        return _firewall;
                    }
                    private PVERrd _rrd;

                    public PVERrd getRrd() {
                        if (_rrd == null) {
                            _rrd = new PVERrd(_client, _node, _vmid);
                        }
                        return _rrd;
                    }
                    private PVERrddata _rrddata;

                    public PVERrddata getRrddata() {
                        if (_rrddata == null) {
                            _rrddata = new PVERrddata(_client, _node, _vmid);
                        }
                        return _rrddata;
                    }
                    private PVEConfig _config;

                    public PVEConfig getConfig() {
                        if (_config == null) {
                            _config = new PVEConfig(_client, _node, _vmid);
                        }
                        return _config;
                    }
                    private PVEPending _pending;

                    public PVEPending getPending() {
                        if (_pending == null) {
                            _pending = new PVEPending(_client, _node, _vmid);
                        }
                        return _pending;
                    }
                    private PVEUnlink _unlink;

                    public PVEUnlink getUnlink() {
                        if (_unlink == null) {
                            _unlink = new PVEUnlink(_client, _node, _vmid);
                        }
                        return _unlink;
                    }
                    private PVEVncproxy _vncproxy;

                    public PVEVncproxy getVncproxy() {
                        if (_vncproxy == null) {
                            _vncproxy = new PVEVncproxy(_client, _node, _vmid);
                        }
                        return _vncproxy;
                    }
                    private PVEVncwebsocket _vncwebsocket;

                    public PVEVncwebsocket getVncwebsocket() {
                        if (_vncwebsocket == null) {
                            _vncwebsocket = new PVEVncwebsocket(_client, _node, _vmid);
                        }
                        return _vncwebsocket;
                    }
                    private PVESpiceproxy _spiceproxy;

                    public PVESpiceproxy getSpiceproxy() {
                        if (_spiceproxy == null) {
                            _spiceproxy = new PVESpiceproxy(_client, _node, _vmid);
                        }
                        return _spiceproxy;
                    }
                    private PVEStatus _status;

                    public PVEStatus getStatus() {
                        if (_status == null) {
                            _status = new PVEStatus(_client, _node, _vmid);
                        }
                        return _status;
                    }
                    private PVESendkey _sendkey;

                    public PVESendkey getSendkey() {
                        if (_sendkey == null) {
                            _sendkey = new PVESendkey(_client, _node, _vmid);
                        }
                        return _sendkey;
                    }
                    private PVEFeature _feature;

                    public PVEFeature getFeature() {
                        if (_feature == null) {
                            _feature = new PVEFeature(_client, _node, _vmid);
                        }
                        return _feature;
                    }
                    private PVEClone _clone;

                    public PVEClone getClone() {
                        if (_clone == null) {
                            _clone = new PVEClone(_client, _node, _vmid);
                        }
                        return _clone;
                    }
                    private PVEMoveDisk _moveDisk;

                    public PVEMoveDisk getMoveDisk() {
                        if (_moveDisk == null) {
                            _moveDisk = new PVEMoveDisk(_client, _node, _vmid);
                        }
                        return _moveDisk;
                    }
                    private PVEMigrate _migrate;

                    public PVEMigrate getMigrate() {
                        if (_migrate == null) {
                            _migrate = new PVEMigrate(_client, _node, _vmid);
                        }
                        return _migrate;
                    }
                    private PVEMonitor _monitor;

                    public PVEMonitor getMonitor() {
                        if (_monitor == null) {
                            _monitor = new PVEMonitor(_client, _node, _vmid);
                        }
                        return _monitor;
                    }
                    private PVEAgent _agent;

                    public PVEAgent getAgent() {
                        if (_agent == null) {
                            _agent = new PVEAgent(_client, _node, _vmid);
                        }
                        return _agent;
                    }
                    private PVEResize _resize;

                    public PVEResize getResize() {
                        if (_resize == null) {
                            _resize = new PVEResize(_client, _node, _vmid);
                        }
                        return _resize;
                    }
                    private PVESnapshot _snapshot;

                    public PVESnapshot getSnapshot() {
                        if (_snapshot == null) {
                            _snapshot = new PVESnapshot(_client, _node, _vmid);
                        }
                        return _snapshot;
                    }
                    private PVETemplate _template;

                    public PVETemplate getTemplate() {
                        if (_template == null) {
                            _template = new PVETemplate(_client, _node, _vmid);
                        }
                        return _template;
                    }

                    public class PVEFirewall extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEFirewall(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }
                        private PVERules _rules;

                        public PVERules getRules() {
                            if (_rules == null) {
                                _rules = new PVERules(_client, _node, _vmid);
                            }
                            return _rules;
                        }
                        private PVEAliases _aliases;

                        public PVEAliases getAliases() {
                            if (_aliases == null) {
                                _aliases = new PVEAliases(_client, _node, _vmid);
                            }
                            return _aliases;
                        }
                        private PVEIpset _ipset;

                        public PVEIpset getIpset() {
                            if (_ipset == null) {
                                _ipset = new PVEIpset(_client, _node, _vmid);
                            }
                            return _ipset;
                        }
                        private PVEOptions _options;

                        public PVEOptions getOptions() {
                            if (_options == null) {
                                _options = new PVEOptions(_client, _node, _vmid);
                            }
                            return _options;
                        }
                        private PVELog _log;

                        public PVELog getLog() {
                            if (_log == null) {
                                _log = new PVELog(_client, _node, _vmid);
                            }
                            return _log;
                        }
                        private PVERefs _refs;

                        public PVERefs getRefs() {
                            if (_refs == null) {
                                _refs = new PVERefs(_client, _node, _vmid);
                            }
                            return _refs;
                        }

                        public class PVERules extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVERules(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            public PVEItemPos get(Object pos) {
                                return new PVEItemPos(_client, _node, _vmid, pos);
                            }

                            public class PVEItemPos extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _pos;

                                protected PVEItemPos(Client client, Object node, Object vmid, Object pos) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _pos = pos;
                                }

                                /**
                                 * Delete rule.
                                 *
                                 * @param digest Prevent changes if current
                                 * configuration file has different SHA1 digest.
                                 * This can be used to prevent concurrent
                                 * modifications.
                                 */
                                public void deleteRule(String digest) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("digest", digest);
                                    _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/rules/" + _pos + "", parameters);
                                }

                                /**
                                 * Delete rule.
                                 */
                                public void deleteRule() throws JSONException {
                                    _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/rules/" + _pos + "", null);
                                }

                                /**
                                 * Get single rule data.
                                 */
                                public JSONObject getRule() throws JSONException {
                                    return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/rules/" + _pos + "", null);
                                }

                                /**
                                 * Modify rule data.
                                 *
                                 * @param action Rule action ('ACCEPT', 'DROP',
                                 * 'REJECT') or security group name.
                                 * @param comment Descriptive comment.
                                 * @param delete A list of settings you want to
                                 * delete.
                                 * @param dest Restrict packet destination
                                 * address. This can refer to a single IP
                                 * address, an IP set ('+ipsetname') or an IP
                                 * alias definition. You can also specify an
                                 * address range like
                                 * '20.34.101.207-201.3.9.99', or a list of IP
                                 * addresses and networks (entries are separated
                                 * by comma). Please do not mix IPv4 and IPv6
                                 * addresses inside such lists.
                                 * @param digest Prevent changes if current
                                 * configuration file has different SHA1 digest.
                                 * This can be used to prevent concurrent
                                 * modifications.
                                 * @param dport Restrict TCP/UDP destination
                                 * port. You can use service names or simple
                                 * numbers (0-65535), as defined in
                                 * '/etc/services'. Port ranges can be specified
                                 * with '\d+:\d+', for example '80:85', and you
                                 * can use comma separated list to match several
                                 * ports or ranges.
                                 * @param enable Flag to enable/disable a rule.
                                 * @param iface Network interface name. You have
                                 * to use network configuration key names for
                                 * VMs and containers ('net\d+'). Host related
                                 * rules can use arbitrary strings.
                                 * @param macro Use predefined standard macro.
                                 * @param moveto Move rule to new position
                                 * &amp;lt;moveto&amp;gt;. Other arguments are
                                 * ignored.
                                 * @param proto IP protocol. You can use
                                 * protocol names ('tcp'/'udp') or simple
                                 * numbers, as defined in '/etc/protocols'.
                                 * @param source Restrict packet source address.
                                 * This can refer to a single IP address, an IP
                                 * set ('+ipsetname') or an IP alias definition.
                                 * You can also specify an address range like
                                 * '20.34.101.207-201.3.9.99', or a list of IP
                                 * addresses and networks (entries are separated
                                 * by comma). Please do not mix IPv4 and IPv6
                                 * addresses inside such lists.
                                 * @param sport Restrict TCP/UDP source port.
                                 * You can use service names or simple numbers
                                 * (0-65535), as defined in '/etc/services'.
                                 * Port ranges can be specified with '\d+:\d+',
                                 * for example '80:85', and you can use comma
                                 * separated list to match several ports or
                                 * ranges.
                                 * @param type Rule type. Enum: in,out,group
                                 */
                                public void updateRule(String action, String comment, String delete, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer moveto, String proto, String source, String sport, String type) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("action", action);
                                    parameters.put("comment", comment);
                                    parameters.put("delete", delete);
                                    parameters.put("dest", dest);
                                    parameters.put("digest", digest);
                                    parameters.put("dport", dport);
                                    parameters.put("enable", enable);
                                    parameters.put("iface", iface);
                                    parameters.put("macro", macro);
                                    parameters.put("moveto", moveto);
                                    parameters.put("proto", proto);
                                    parameters.put("source", source);
                                    parameters.put("sport", sport);
                                    parameters.put("type", type);
                                    _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/rules/" + _pos + "", parameters);
                                }

                                /**
                                 * Modify rule data.
                                 */
                                public void updateRule() throws JSONException {
                                    _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/rules/" + _pos + "", null);
                                }
                            }

                            /**
                             * List rules.
                             */
                            public JSONObject getRules() throws JSONException {
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/rules", null);
                            }

                            /**
                             * Create new rule.
                             *
                             * @param action Rule action ('ACCEPT', 'DROP',
                             * 'REJECT') or security group name.
                             * @param type Rule type. Enum: in,out,group
                             * @param comment Descriptive comment.
                             * @param dest Restrict packet destination address.
                             * This can refer to a single IP address, an IP set
                             * ('+ipsetname') or an IP alias definition. You can
                             * also specify an address range like
                             * '20.34.101.207-201.3.9.99', or a list of IP
                             * addresses and networks (entries are separated by
                             * comma). Please do not mix IPv4 and IPv6 addresses
                             * inside such lists.
                             * @param digest Prevent changes if current
                             * configuration file has different SHA1 digest.
                             * This can be used to prevent concurrent
                             * modifications.
                             * @param dport Restrict TCP/UDP destination port.
                             * You can use service names or simple numbers
                             * (0-65535), as defined in '/etc/services'. Port
                             * ranges can be specified with '\d+:\d+', for
                             * example '80:85', and you can use comma separated
                             * list to match several ports or ranges.
                             * @param enable Flag to enable/disable a rule.
                             * @param iface Network interface name. You have to
                             * use network configuration key names for VMs and
                             * containers ('net\d+'). Host related rules can use
                             * arbitrary strings.
                             * @param macro Use predefined standard macro.
                             * @param pos Update rule at position
                             * &amp;lt;pos&amp;gt;.
                             * @param proto IP protocol. You can use protocol
                             * names ('tcp'/'udp') or simple numbers, as defined
                             * in '/etc/protocols'.
                             * @param source Restrict packet source address.
                             * This can refer to a single IP address, an IP set
                             * ('+ipsetname') or an IP alias definition. You can
                             * also specify an address range like
                             * '20.34.101.207-201.3.9.99', or a list of IP
                             * addresses and networks (entries are separated by
                             * comma). Please do not mix IPv4 and IPv6 addresses
                             * inside such lists.
                             * @param sport Restrict TCP/UDP source port. You
                             * can use service names or simple numbers
                             * (0-65535), as defined in '/etc/services'. Port
                             * ranges can be specified with '\d+:\d+', for
                             * example '80:85', and you can use comma separated
                             * list to match several ports or ranges.
                             */
                            public void createRule(String action, String type, String comment, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer pos, String proto, String source, String sport) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("action", action);
                                parameters.put("type", type);
                                parameters.put("comment", comment);
                                parameters.put("dest", dest);
                                parameters.put("digest", digest);
                                parameters.put("dport", dport);
                                parameters.put("enable", enable);
                                parameters.put("iface", iface);
                                parameters.put("macro", macro);
                                parameters.put("pos", pos);
                                parameters.put("proto", proto);
                                parameters.put("source", source);
                                parameters.put("sport", sport);
                                _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/rules", parameters);
                            }

                            /**
                             * Create new rule.
                             *
                             * @param action Rule action ('ACCEPT', 'DROP',
                             * 'REJECT') or security group name.
                             * @param type Rule type. Enum: in,out,group
                             */
                            public void createRule(String action, String type) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("action", action);
                                parameters.put("type", type);
                                _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/rules", parameters);
                            }
                        }

                        public class PVEAliases extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEAliases(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            public PVEItemName get(Object name) {
                                return new PVEItemName(_client, _node, _vmid, name);
                            }

                            public class PVEItemName extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _name;

                                protected PVEItemName(Client client, Object node, Object vmid, Object name) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _name = name;
                                }

                                /**
                                 * Remove IP or Network alias.
                                 *
                                 * @param digest Prevent changes if current
                                 * configuration file has different SHA1 digest.
                                 * This can be used to prevent concurrent
                                 * modifications.
                                 */
                                public void removeAlias(String digest) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("digest", digest);
                                    _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/aliases/" + _name + "", parameters);
                                }

                                /**
                                 * Remove IP or Network alias.
                                 */
                                public void removeAlias() throws JSONException {
                                    _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/aliases/" + _name + "", null);
                                }

                                /**
                                 * Read alias.
                                 */
                                public JSONObject readAlias() throws JSONException {
                                    return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/aliases/" + _name + "", null);
                                }

                                /**
                                 * Update IP or Network alias.
                                 *
                                 * @param cidr Network/IP specification in CIDR
                                 * format.
                                 * @param comment
                                 * @param digest Prevent changes if current
                                 * configuration file has different SHA1 digest.
                                 * This can be used to prevent concurrent
                                 * modifications.
                                 * @param rename Rename an existing alias.
                                 */
                                public void updateAlias(String cidr, String comment, String digest, String rename) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("cidr", cidr);
                                    parameters.put("comment", comment);
                                    parameters.put("digest", digest);
                                    parameters.put("rename", rename);
                                    _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/aliases/" + _name + "", parameters);
                                }

                                /**
                                 * Update IP or Network alias.
                                 *
                                 * @param cidr Network/IP specification in CIDR
                                 * format.
                                 */
                                public void updateAlias(String cidr) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("cidr", cidr);
                                    _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/aliases/" + _name + "", parameters);
                                }
                            }

                            /**
                             * List aliases
                             */
                            public JSONObject getAliases() throws JSONException {
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/aliases", null);
                            }

                            /**
                             * Create IP or Network Alias.
                             *
                             * @param cidr Network/IP specification in CIDR
                             * format.
                             * @param name Alias name.
                             * @param comment
                             */
                            public void createAlias(String cidr, String name, String comment) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("cidr", cidr);
                                parameters.put("name", name);
                                parameters.put("comment", comment);
                                _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/aliases", parameters);
                            }

                            /**
                             * Create IP or Network Alias.
                             *
                             * @param cidr Network/IP specification in CIDR
                             * format.
                             * @param name Alias name.
                             */
                            public void createAlias(String cidr, String name) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("cidr", cidr);
                                parameters.put("name", name);
                                _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/aliases", parameters);
                            }
                        }

                        public class PVEIpset extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEIpset(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            public PVEItemName get(Object name) {
                                return new PVEItemName(_client, _node, _vmid, name);
                            }

                            public class PVEItemName extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _name;

                                protected PVEItemName(Client client, Object node, Object vmid, Object name) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _name = name;
                                }

                                public PVEItemCidr get(Object cidr) {
                                    return new PVEItemCidr(_client, _node, _vmid, _name, cidr);
                                }

                                public class PVEItemCidr extends Base {

                                    private Object _node;
                                    private Object _vmid;
                                    private Object _name;
                                    private Object _cidr;

                                    protected PVEItemCidr(Client client, Object node, Object vmid, Object name, Object cidr) {
                                        _client = client;
                                        _node = node;
                                        _vmid = vmid;
                                        _name = name;
                                        _cidr = cidr;
                                    }

                                    /**
                                     * Remove IP or Network from IPSet.
                                     *
                                     * @param digest Prevent changes if current
                                     * configuration file has different SHA1
                                     * digest. This can be used to prevent
                                     * concurrent modifications.
                                     */
                                    public void removeIp(String digest) throws JSONException {
                                        Map<String, Object> parameters = new HashMap<String, Object>();
                                        parameters.put("digest", digest);
                                        _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", parameters);
                                    }

                                    /**
                                     * Remove IP or Network from IPSet.
                                     */
                                    public void removeIp() throws JSONException {
                                        _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", null);
                                    }

                                    /**
                                     * Read IP or Network settings from IPSet.
                                     */
                                    public JSONObject readIp() throws JSONException {
                                        return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", null);
                                    }

                                    /**
                                     * Update IP or Network settings
                                     *
                                     * @param comment
                                     * @param digest Prevent changes if current
                                     * configuration file has different SHA1
                                     * digest. This can be used to prevent
                                     * concurrent modifications.
                                     * @param nomatch
                                     */
                                    public void updateIp(String comment, String digest, Boolean nomatch) throws JSONException {
                                        Map<String, Object> parameters = new HashMap<String, Object>();
                                        parameters.put("comment", comment);
                                        parameters.put("digest", digest);
                                        parameters.put("nomatch", nomatch);
                                        _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", parameters);
                                    }

                                    /**
                                     * Update IP or Network settings
                                     */
                                    public void updateIp() throws JSONException {
                                        _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", null);
                                    }
                                }

                                /**
                                 * Delete IPSet
                                 */
                                public void deleteIpset() throws JSONException {
                                    _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "", null);
                                }

                                /**
                                 * List IPSet content
                                 */
                                public JSONObject getIpset() throws JSONException {
                                    return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "", null);
                                }

                                /**
                                 * Add IP or Network to IPSet.
                                 *
                                 * @param cidr Network/IP specification in CIDR
                                 * format.
                                 * @param comment
                                 * @param nomatch
                                 */
                                public void createIp(String cidr, String comment, Boolean nomatch) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("cidr", cidr);
                                    parameters.put("comment", comment);
                                    parameters.put("nomatch", nomatch);
                                    _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "", parameters);
                                }

                                /**
                                 * Add IP or Network to IPSet.
                                 *
                                 * @param cidr Network/IP specification in CIDR
                                 * format.
                                 */
                                public void createIp(String cidr) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("cidr", cidr);
                                    _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset/" + _name + "", parameters);
                                }
                            }

                            /**
                             * List IPSets
                             */
                            public JSONObject ipsetIndex() throws JSONException {
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset", null);
                            }

                            /**
                             * Create new IPSet
                             *
                             * @param name IP set name.
                             * @param comment
                             * @param digest Prevent changes if current
                             * configuration file has different SHA1 digest.
                             * This can be used to prevent concurrent
                             * modifications.
                             * @param rename Rename an existing IPSet. You can
                             * set 'rename' to the same value as 'name' to
                             * update the 'comment' of an existing IPSet.
                             */
                            public void createIpset(String name, String comment, String digest, String rename) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("name", name);
                                parameters.put("comment", comment);
                                parameters.put("digest", digest);
                                parameters.put("rename", rename);
                                _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset", parameters);
                            }

                            /**
                             * Create new IPSet
                             *
                             * @param name IP set name.
                             */
                            public void createIpset(String name) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("name", name);
                                _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/ipset", parameters);
                            }
                        }

                        public class PVEOptions extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEOptions(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Get VM firewall options.
                             */
                            public JSONObject getOptions() throws JSONException {
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/options", null);
                            }

                            /**
                             * Set Firewall options.
                             *
                             * @param delete A list of settings you want to
                             * delete.
                             * @param dhcp Enable DHCP.
                             * @param digest Prevent changes if current
                             * configuration file has different SHA1 digest.
                             * This can be used to prevent concurrent
                             * modifications.
                             * @param enable Enable/disable firewall rules.
                             * @param ipfilter Enable default IP filters. This
                             * is equivalent to adding an empty
                             * ipfilter-net&amp;lt;id&amp;gt; ipset for every
                             * interface. Such ipsets implicitly contain sane
                             * default restrictions such as restricting IPv6
                             * link local addresses to the one derived from the
                             * interface's MAC address. For containers the
                             * configured IP addresses will be implicitly added.
                             * @param log_level_in Log level for incoming
                             * traffic. Enum:
                             * emerg,alert,crit,err,warning,notice,info,debug,nolog
                             * @param log_level_out Log level for outgoing
                             * traffic. Enum:
                             * emerg,alert,crit,err,warning,notice,info,debug,nolog
                             * @param macfilter Enable/disable MAC address
                             * filter.
                             * @param ndp Enable NDP.
                             * @param policy_in Input policy. Enum:
                             * ACCEPT,REJECT,DROP
                             * @param policy_out Output policy. Enum:
                             * ACCEPT,REJECT,DROP
                             * @param radv Allow sending Router Advertisement.
                             */
                            public void setOptions(String delete, Boolean dhcp, String digest, Boolean enable, Boolean ipfilter, String log_level_in, String log_level_out, Boolean macfilter, Boolean ndp, String policy_in, String policy_out, Boolean radv) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("delete", delete);
                                parameters.put("dhcp", dhcp);
                                parameters.put("digest", digest);
                                parameters.put("enable", enable);
                                parameters.put("ipfilter", ipfilter);
                                parameters.put("log_level_in", log_level_in);
                                parameters.put("log_level_out", log_level_out);
                                parameters.put("macfilter", macfilter);
                                parameters.put("ndp", ndp);
                                parameters.put("policy_in", policy_in);
                                parameters.put("policy_out", policy_out);
                                parameters.put("radv", radv);
                                _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/options", parameters);
                            }

                            /**
                             * Set Firewall options.
                             */
                            public void setOptions() throws JSONException {
                                _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/options", null);
                            }
                        }

                        public class PVELog extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVELog(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Read firewall log
                             *
                             * @param limit
                             * @param start
                             */
                            public JSONObject log(Integer limit, Integer start) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("limit", limit);
                                parameters.put("start", start);
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/log", parameters);
                            }

                            /**
                             * Read firewall log
                             */
                            public JSONObject log() throws JSONException {
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/log", null);
                            }
                        }

                        public class PVERefs extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVERefs(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Lists possible IPSet/Alias reference which are
                             * allowed in source/dest properties.
                             *
                             * @param type Only list references of specified
                             * type. Enum: alias,ipset
                             */
                            public JSONObject refs(String type) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("type", type);
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/refs", parameters);
                            }

                            /**
                             * Lists possible IPSet/Alias reference which are
                             * allowed in source/dest properties.
                             */
                            public JSONObject refs() throws JSONException {
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall/refs", null);
                            }
                        }

                        /**
                         * Directory index.
                         */
                        public JSONObject index() throws JSONException {
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/firewall", null);
                        }
                    }

                    public class PVERrd extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVERrd(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Read VM RRD statistics (returns PNG)
                         *
                         * @param ds The list of datasources you want to
                         * display.
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         * @param cf The RRD consolidation function Enum:
                         * AVERAGE,MAX
                         */
                        public JSONObject rrd(String ds, String timeframe, String cf) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("ds", ds);
                            parameters.put("timeframe", timeframe);
                            parameters.put("cf", cf);
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/rrd", parameters);
                        }

                        /**
                         * Read VM RRD statistics (returns PNG)
                         *
                         * @param ds The list of datasources you want to
                         * display.
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         */
                        public JSONObject rrd(String ds, String timeframe) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("ds", ds);
                            parameters.put("timeframe", timeframe);
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/rrd", parameters);
                        }
                    }

                    public class PVERrddata extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVERrddata(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Read VM RRD statistics
                         *
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         * @param cf The RRD consolidation function Enum:
                         * AVERAGE,MAX
                         */
                        public JSONObject rrddata(String timeframe, String cf) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("timeframe", timeframe);
                            parameters.put("cf", cf);
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/rrddata", parameters);
                        }

                        /**
                         * Read VM RRD statistics
                         *
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         */
                        public JSONObject rrddata(String timeframe) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("timeframe", timeframe);
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/rrddata", parameters);
                        }
                    }

                    public class PVEConfig extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEConfig(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Get current virtual machine configuration. This does
                         * not include pending configuration changes (see
                         * 'pending' API).
                         *
                         * @param current Get current values (instead of pending
                         * values).
                         */
                        public JSONObject vmConfig(Boolean current) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("current", current);
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/config", parameters);
                        }

                        /**
                         * Get current virtual machine configuration. This does
                         * not include pending configuration changes (see
                         * 'pending' API).
                         */
                        public JSONObject vmConfig() throws JSONException {
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/config", null);
                        }

                        /**
                         * Set virtual machine options (asynchrounous API).
                         *
                         * @param acpi Enable/disable ACPI.
                         * @param agent Enable/disable Qemu GuestAgent.
                         * @param args Arbitrary arguments passed to kvm.
                         * @param autostart Automatic restart after crash
                         * (currently ignored).
                         * @param background_delay Time to wait for the task to
                         * finish. We return 'null' if the task finish within
                         * that time.
                         * @param balloon Amount of target RAM for the VM in MB.
                         * Using zero disables the ballon driver.
                         * @param bios Select BIOS implementation. Enum:
                         * seabios,ovmf
                         * @param boot Boot on floppy (a), hard disk (c), CD-ROM
                         * (d), or network (n).
                         * @param bootdisk Enable booting from specified disk.
                         * @param cdrom This is an alias for option -ide2
                         * @param cores The number of cores per socket.
                         * @param cpu Emulated CPU type.
                         * @param cpulimit Limit of CPU usage.
                         * @param cpuunits CPU weight for a VM.
                         * @param delete A list of settings you want to delete.
                         * @param description Description for the VM. Only used
                         * on the configuration web interface. This is saved as
                         * comment inside the configuration file.
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         * @param force Force physical removal. Without this, we
                         * simple remove the disk from the config file and
                         * create an additional configuration entry called
                         * 'unused[n]', which contains the volume ID. Unlink of
                         * unused[n] always cause physical removal.
                         * @param freeze Freeze CPU at startup (use 'c' monitor
                         * command to start execution).
                         * @param hostpciN Map host PCI devices into guest.
                         * @param hotplug Selectively enable hotplug features.
                         * This is a comma separated list of hotplug features:
                         * 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0'
                         * to disable hotplug completely. Value '1' is an alias
                         * for the default 'network,disk,usb'.
                         * @param hugepages Enable/disable hugepages memory.
                         * Enum: any,2,1024
                         * @param ideN Use volume as IDE hard disk or CD-ROM (n
                         * is 0 to 3).
                         * @param keyboard Keybord layout for vnc server.
                         * Default is read from the '/etc/pve/datacenter.conf'
                         * configuration file. Enum:
                         * de,de-ch,da,en-gb,en-us,es,fi,fr,fr-be,fr-ca,fr-ch,hu,is,it,ja,lt,mk,nl,no,pl,pt,pt-br,sv,sl,tr
                         * @param kvm Enable/disable KVM hardware
                         * virtualization.
                         * @param localtime Set the real time clock to local
                         * time. This is enabled by default if ostype indicates
                         * a Microsoft OS.
                         * @param lock_ Lock/unlock the VM. Enum:
                         * migrate,backup,snapshot,rollback
                         * @param machine Specific the Qemu machine type.
                         * @param memory Amount of RAM for the VM in MB. This is
                         * the maximum available memory when you use the balloon
                         * device.
                         * @param migrate_downtime Set maximum tolerated
                         * downtime (in seconds) for migrations.
                         * @param migrate_speed Set maximum speed (in MB/s) for
                         * migrations. Value 0 is no limit.
                         * @param name Set a name for the VM. Only used on the
                         * configuration web interface.
                         * @param netN Specify network devices.
                         * @param numa Enable/disable NUMA.
                         * @param numaN NUMA topology.
                         * @param onboot Specifies whether a VM will be started
                         * during system bootup.
                         * @param ostype Specify guest operating system. Enum:
                         * other,wxp,w2k,w2k3,w2k8,wvista,win7,win8,win10,l24,l26,solaris
                         * @param parallelN Map host parallel devices (n is 0 to
                         * 2).
                         * @param protection Sets the protection flag of the VM.
                         * This will disable the remove VM and remove disk
                         * operations.
                         * @param reboot Allow reboot. If set to '0' the VM exit
                         * on reboot.
                         * @param revert Revert a pending change.
                         * @param sataN Use volume as SATA hard disk or CD-ROM
                         * (n is 0 to 5).
                         * @param scsiN Use volume as SCSI hard disk or CD-ROM
                         * (n is 0 to 13).
                         * @param scsihw SCSI controller model Enum:
                         * lsi,lsi53c810,virtio-scsi-pci,virtio-scsi-single,megasas,pvscsi
                         * @param serialN Create a serial device inside the VM
                         * (n is 0 to 3)
                         * @param shares Amount of memory shares for
                         * auto-ballooning. The larger the number is, the more
                         * memory this VM gets. Number is relative to weights of
                         * all other running VMs. Using zero disables
                         * auto-ballooning
                         * @param skiplock Ignore locks - only root is allowed
                         * to use this option.
                         * @param smbios1 Specify SMBIOS type 1 fields.
                         * @param smp The number of CPUs. Please use option
                         * -sockets instead.
                         * @param sockets The number of CPU sockets.
                         * @param startdate Set the initial date of the real
                         * time clock. Valid format for date are: 'now' or
                         * '2006-06-17T16:01:21' or '2006-06-17'.
                         * @param startup Startup and shutdown behavior. Order
                         * is a non-negative number defining the general startup
                         * order. Shutdown in done with reverse ordering.
                         * Additionally you can set the 'up' or 'down' delay in
                         * seconds, which specifies a delay to wait before the
                         * next VM is started or stopped.
                         * @param tablet Enable/disable the USB tablet device.
                         * @param tdf Enable/disable time drift fix.
                         * @param template Enable/disable Template.
                         * @param unusedN Reference to unused volumes. This is
                         * used internally, and should not be modified manually.
                         * @param usbN Configure an USB device (n is 0 to 4).
                         * @param vcpus Number of hotplugged vcpus.
                         * @param vga Select the VGA type. Enum:
                         * std,cirrus,vmware,qxl,serial0,serial1,serial2,serial3,qxl2,qxl3,qxl4
                         * @param virtioN Use volume as VIRTIO hard disk (n is 0
                         * to 15).
                         * @param watchdog Create a virtual hardware watchdog
                         * device.
                         */
                        public JSONObject updateVmAsync(Boolean acpi, Boolean agent, String args, Boolean autostart, Integer background_delay, Integer balloon, String bios, String boot, String bootdisk, String cdrom, Integer cores, String cpu, Integer cpulimit, Integer cpuunits, String delete, String description, String digest, Boolean force, Boolean freeze, Map<Integer, String> hostpciN, String hotplug, String hugepages, Map<Integer, String> ideN, String keyboard, Boolean kvm, Boolean localtime, String lock_, String machine, Integer memory, Integer migrate_downtime, Integer migrate_speed, String name, Map<Integer, String> netN, Boolean numa, Map<Integer, String> numaN, Boolean onboot, String ostype, Map<Integer, String> parallelN, Boolean protection, Boolean reboot, String revert, Map<Integer, String> sataN, Map<Integer, String> scsiN, String scsihw, Map<Integer, String> serialN, Integer shares, Boolean skiplock, String smbios1, Integer smp, Integer sockets, String startdate, String startup, Boolean tablet, Boolean tdf, Boolean template, Map<Integer, String> unusedN, Map<Integer, String> usbN, Integer vcpus, String vga, Map<Integer, String> virtioN, String watchdog) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("acpi", acpi);
                            parameters.put("agent", agent);
                            parameters.put("args", args);
                            parameters.put("autostart", autostart);
                            parameters.put("background_delay", background_delay);
                            parameters.put("balloon", balloon);
                            parameters.put("bios", bios);
                            parameters.put("boot", boot);
                            parameters.put("bootdisk", bootdisk);
                            parameters.put("cdrom", cdrom);
                            parameters.put("cores", cores);
                            parameters.put("cpu", cpu);
                            parameters.put("cpulimit", cpulimit);
                            parameters.put("cpuunits", cpuunits);
                            parameters.put("delete", delete);
                            parameters.put("description", description);
                            parameters.put("digest", digest);
                            parameters.put("force", force);
                            parameters.put("freeze", freeze);
                            parameters.put("hotplug", hotplug);
                            parameters.put("hugepages", hugepages);
                            parameters.put("keyboard", keyboard);
                            parameters.put("kvm", kvm);
                            parameters.put("localtime", localtime);
                            parameters.put("lock", lock_);
                            parameters.put("machine", machine);
                            parameters.put("memory", memory);
                            parameters.put("migrate_downtime", migrate_downtime);
                            parameters.put("migrate_speed", migrate_speed);
                            parameters.put("name", name);
                            parameters.put("numa", numa);
                            parameters.put("onboot", onboot);
                            parameters.put("ostype", ostype);
                            parameters.put("protection", protection);
                            parameters.put("reboot", reboot);
                            parameters.put("revert", revert);
                            parameters.put("scsihw", scsihw);
                            parameters.put("shares", shares);
                            parameters.put("skiplock", skiplock);
                            parameters.put("smbios1", smbios1);
                            parameters.put("smp", smp);
                            parameters.put("sockets", sockets);
                            parameters.put("startdate", startdate);
                            parameters.put("startup", startup);
                            parameters.put("tablet", tablet);
                            parameters.put("tdf", tdf);
                            parameters.put("template", template);
                            parameters.put("vcpus", vcpus);
                            parameters.put("vga", vga);
                            parameters.put("watchdog", watchdog);
                            addIndexedParmeter(parameters, "hostpci", hostpciN);
                            addIndexedParmeter(parameters, "ide", ideN);
                            addIndexedParmeter(parameters, "net", netN);
                            addIndexedParmeter(parameters, "numa", numaN);
                            addIndexedParmeter(parameters, "parallel", parallelN);
                            addIndexedParmeter(parameters, "sata", sataN);
                            addIndexedParmeter(parameters, "scsi", scsiN);
                            addIndexedParmeter(parameters, "serial", serialN);
                            addIndexedParmeter(parameters, "unused", unusedN);
                            addIndexedParmeter(parameters, "usb", usbN);
                            addIndexedParmeter(parameters, "virtio", virtioN);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/config", parameters);
                        }

                        /**
                         * Set virtual machine options (asynchrounous API).
                         */
                        public JSONObject updateVmAsync() throws JSONException {
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/config", null);
                        }

                        /**
                         * Set virtual machine options (synchrounous API) - You
                         * should consider using the POST method instead for any
                         * actions involving hotplug or storage allocation.
                         *
                         * @param acpi Enable/disable ACPI.
                         * @param agent Enable/disable Qemu GuestAgent.
                         * @param args Arbitrary arguments passed to kvm.
                         * @param autostart Automatic restart after crash
                         * (currently ignored).
                         * @param balloon Amount of target RAM for the VM in MB.
                         * Using zero disables the ballon driver.
                         * @param bios Select BIOS implementation. Enum:
                         * seabios,ovmf
                         * @param boot Boot on floppy (a), hard disk (c), CD-ROM
                         * (d), or network (n).
                         * @param bootdisk Enable booting from specified disk.
                         * @param cdrom This is an alias for option -ide2
                         * @param cores The number of cores per socket.
                         * @param cpu Emulated CPU type.
                         * @param cpulimit Limit of CPU usage.
                         * @param cpuunits CPU weight for a VM.
                         * @param delete A list of settings you want to delete.
                         * @param description Description for the VM. Only used
                         * on the configuration web interface. This is saved as
                         * comment inside the configuration file.
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         * @param force Force physical removal. Without this, we
                         * simple remove the disk from the config file and
                         * create an additional configuration entry called
                         * 'unused[n]', which contains the volume ID. Unlink of
                         * unused[n] always cause physical removal.
                         * @param freeze Freeze CPU at startup (use 'c' monitor
                         * command to start execution).
                         * @param hostpciN Map host PCI devices into guest.
                         * @param hotplug Selectively enable hotplug features.
                         * This is a comma separated list of hotplug features:
                         * 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0'
                         * to disable hotplug completely. Value '1' is an alias
                         * for the default 'network,disk,usb'.
                         * @param hugepages Enable/disable hugepages memory.
                         * Enum: any,2,1024
                         * @param ideN Use volume as IDE hard disk or CD-ROM (n
                         * is 0 to 3).
                         * @param keyboard Keybord layout for vnc server.
                         * Default is read from the '/etc/pve/datacenter.conf'
                         * configuration file. Enum:
                         * de,de-ch,da,en-gb,en-us,es,fi,fr,fr-be,fr-ca,fr-ch,hu,is,it,ja,lt,mk,nl,no,pl,pt,pt-br,sv,sl,tr
                         * @param kvm Enable/disable KVM hardware
                         * virtualization.
                         * @param localtime Set the real time clock to local
                         * time. This is enabled by default if ostype indicates
                         * a Microsoft OS.
                         * @param lock_ Lock/unlock the VM. Enum:
                         * migrate,backup,snapshot,rollback
                         * @param machine Specific the Qemu machine type.
                         * @param memory Amount of RAM for the VM in MB. This is
                         * the maximum available memory when you use the balloon
                         * device.
                         * @param migrate_downtime Set maximum tolerated
                         * downtime (in seconds) for migrations.
                         * @param migrate_speed Set maximum speed (in MB/s) for
                         * migrations. Value 0 is no limit.
                         * @param name Set a name for the VM. Only used on the
                         * configuration web interface.
                         * @param netN Specify network devices.
                         * @param numa Enable/disable NUMA.
                         * @param numaN NUMA topology.
                         * @param onboot Specifies whether a VM will be started
                         * during system bootup.
                         * @param ostype Specify guest operating system. Enum:
                         * other,wxp,w2k,w2k3,w2k8,wvista,win7,win8,win10,l24,l26,solaris
                         * @param parallelN Map host parallel devices (n is 0 to
                         * 2).
                         * @param protection Sets the protection flag of the VM.
                         * This will disable the remove VM and remove disk
                         * operations.
                         * @param reboot Allow reboot. If set to '0' the VM exit
                         * on reboot.
                         * @param revert Revert a pending change.
                         * @param sataN Use volume as SATA hard disk or CD-ROM
                         * (n is 0 to 5).
                         * @param scsiN Use volume as SCSI hard disk or CD-ROM
                         * (n is 0 to 13).
                         * @param scsihw SCSI controller model Enum:
                         * lsi,lsi53c810,virtio-scsi-pci,virtio-scsi-single,megasas,pvscsi
                         * @param serialN Create a serial device inside the VM
                         * (n is 0 to 3)
                         * @param shares Amount of memory shares for
                         * auto-ballooning. The larger the number is, the more
                         * memory this VM gets. Number is relative to weights of
                         * all other running VMs. Using zero disables
                         * auto-ballooning
                         * @param skiplock Ignore locks - only root is allowed
                         * to use this option.
                         * @param smbios1 Specify SMBIOS type 1 fields.
                         * @param smp The number of CPUs. Please use option
                         * -sockets instead.
                         * @param sockets The number of CPU sockets.
                         * @param startdate Set the initial date of the real
                         * time clock. Valid format for date are: 'now' or
                         * '2006-06-17T16:01:21' or '2006-06-17'.
                         * @param startup Startup and shutdown behavior. Order
                         * is a non-negative number defining the general startup
                         * order. Shutdown in done with reverse ordering.
                         * Additionally you can set the 'up' or 'down' delay in
                         * seconds, which specifies a delay to wait before the
                         * next VM is started or stopped.
                         * @param tablet Enable/disable the USB tablet device.
                         * @param tdf Enable/disable time drift fix.
                         * @param template Enable/disable Template.
                         * @param unusedN Reference to unused volumes. This is
                         * used internally, and should not be modified manually.
                         * @param usbN Configure an USB device (n is 0 to 4).
                         * @param vcpus Number of hotplugged vcpus.
                         * @param vga Select the VGA type. Enum:
                         * std,cirrus,vmware,qxl,serial0,serial1,serial2,serial3,qxl2,qxl3,qxl4
                         * @param virtioN Use volume as VIRTIO hard disk (n is 0
                         * to 15).
                         * @param watchdog Create a virtual hardware watchdog
                         * device.
                         */
                        public void updateVm(Boolean acpi, Boolean agent, String args, Boolean autostart, Integer balloon, String bios, String boot, String bootdisk, String cdrom, Integer cores, String cpu, Integer cpulimit, Integer cpuunits, String delete, String description, String digest, Boolean force, Boolean freeze, Map<Integer, String> hostpciN, String hotplug, String hugepages, Map<Integer, String> ideN, String keyboard, Boolean kvm, Boolean localtime, String lock_, String machine, Integer memory, Integer migrate_downtime, Integer migrate_speed, String name, Map<Integer, String> netN, Boolean numa, Map<Integer, String> numaN, Boolean onboot, String ostype, Map<Integer, String> parallelN, Boolean protection, Boolean reboot, String revert, Map<Integer, String> sataN, Map<Integer, String> scsiN, String scsihw, Map<Integer, String> serialN, Integer shares, Boolean skiplock, String smbios1, Integer smp, Integer sockets, String startdate, String startup, Boolean tablet, Boolean tdf, Boolean template, Map<Integer, String> unusedN, Map<Integer, String> usbN, Integer vcpus, String vga, Map<Integer, String> virtioN, String watchdog) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("acpi", acpi);
                            parameters.put("agent", agent);
                            parameters.put("args", args);
                            parameters.put("autostart", autostart);
                            parameters.put("balloon", balloon);
                            parameters.put("bios", bios);
                            parameters.put("boot", boot);
                            parameters.put("bootdisk", bootdisk);
                            parameters.put("cdrom", cdrom);
                            parameters.put("cores", cores);
                            parameters.put("cpu", cpu);
                            parameters.put("cpulimit", cpulimit);
                            parameters.put("cpuunits", cpuunits);
                            parameters.put("delete", delete);
                            parameters.put("description", description);
                            parameters.put("digest", digest);
                            parameters.put("force", force);
                            parameters.put("freeze", freeze);
                            parameters.put("hotplug", hotplug);
                            parameters.put("hugepages", hugepages);
                            parameters.put("keyboard", keyboard);
                            parameters.put("kvm", kvm);
                            parameters.put("localtime", localtime);
                            parameters.put("lock", lock_);
                            parameters.put("machine", machine);
                            parameters.put("memory", memory);
                            parameters.put("migrate_downtime", migrate_downtime);
                            parameters.put("migrate_speed", migrate_speed);
                            parameters.put("name", name);
                            parameters.put("numa", numa);
                            parameters.put("onboot", onboot);
                            parameters.put("ostype", ostype);
                            parameters.put("protection", protection);
                            parameters.put("reboot", reboot);
                            parameters.put("revert", revert);
                            parameters.put("scsihw", scsihw);
                            parameters.put("shares", shares);
                            parameters.put("skiplock", skiplock);
                            parameters.put("smbios1", smbios1);
                            parameters.put("smp", smp);
                            parameters.put("sockets", sockets);
                            parameters.put("startdate", startdate);
                            parameters.put("startup", startup);
                            parameters.put("tablet", tablet);
                            parameters.put("tdf", tdf);
                            parameters.put("template", template);
                            parameters.put("vcpus", vcpus);
                            parameters.put("vga", vga);
                            parameters.put("watchdog", watchdog);
                            addIndexedParmeter(parameters, "hostpci", hostpciN);
                            addIndexedParmeter(parameters, "ide", ideN);
                            addIndexedParmeter(parameters, "net", netN);
                            addIndexedParmeter(parameters, "numa", numaN);
                            addIndexedParmeter(parameters, "parallel", parallelN);
                            addIndexedParmeter(parameters, "sata", sataN);
                            addIndexedParmeter(parameters, "scsi", scsiN);
                            addIndexedParmeter(parameters, "serial", serialN);
                            addIndexedParmeter(parameters, "unused", unusedN);
                            addIndexedParmeter(parameters, "usb", usbN);
                            addIndexedParmeter(parameters, "virtio", virtioN);
                            _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/config", parameters);
                        }

                        /**
                         * Set virtual machine options (synchrounous API) - You
                         * should consider using the POST method instead for any
                         * actions involving hotplug or storage allocation.
                         */
                        public void updateVm() throws JSONException {
                            _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/config", null);
                        }
                    }

                    public class PVEPending extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEPending(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Get virtual machine configuration, including pending
                         * changes.
                         */
                        public JSONObject vmPending() throws JSONException {
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/pending", null);
                        }
                    }

                    public class PVEUnlink extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEUnlink(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Unlink/delete disk images.
                         *
                         * @param idlist A list of disk IDs you want to delete.
                         * @param force Force physical removal. Without this, we
                         * simple remove the disk from the config file and
                         * create an additional configuration entry called
                         * 'unused[n]', which contains the volume ID. Unlink of
                         * unused[n] always cause physical removal.
                         */
                        public void unlink(String idlist, Boolean force) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("idlist", idlist);
                            parameters.put("force", force);
                            _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/unlink", parameters);
                        }

                        /**
                         * Unlink/delete disk images.
                         *
                         * @param idlist A list of disk IDs you want to delete.
                         */
                        public void unlink(String idlist) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("idlist", idlist);
                            _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/unlink", parameters);
                        }
                    }

                    public class PVEVncproxy extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEVncproxy(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Creates a TCP VNC proxy connections.
                         *
                         * @param websocket starts websockify instead of
                         * vncproxy
                         */
                        public JSONObject vncproxy(Boolean websocket) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("websocket", websocket);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/vncproxy", parameters);
                        }

                        /**
                         * Creates a TCP VNC proxy connections.
                         */
                        public JSONObject vncproxy() throws JSONException {
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/vncproxy", null);
                        }
                    }

                    public class PVEVncwebsocket extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEVncwebsocket(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Opens a weksocket for VNC traffic.
                         *
                         * @param port Port number returned by previous vncproxy
                         * call.
                         * @param vncticket Ticket from previous call to
                         * vncproxy.
                         */
                        public JSONObject vncwebsocket(int port, String vncticket) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("port", port);
                            parameters.put("vncticket", vncticket);
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/vncwebsocket", parameters);
                        }
                    }

                    public class PVESpiceproxy extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVESpiceproxy(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Returns a SPICE configuration to connect to the VM.
                         *
                         * @param proxy SPICE proxy server. This can be used by
                         * the client to specify the proxy server. All nodes in
                         * a cluster runs 'spiceproxy', so it is up to the
                         * client to choose one. By default, we return the node
                         * where the VM is currently running. As resonable
                         * setting is to use same node you use to connect to the
                         * API (This is window.location.hostname for the JS
                         * GUI).
                         */
                        public JSONObject spiceproxy(String proxy) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("proxy", proxy);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/spiceproxy", parameters);
                        }

                        /**
                         * Returns a SPICE configuration to connect to the VM.
                         */
                        public JSONObject spiceproxy() throws JSONException {
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/spiceproxy", null);
                        }
                    }

                    public class PVEStatus extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEStatus(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }
                        private PVECurrent _current;

                        public PVECurrent getCurrent() {
                            if (_current == null) {
                                _current = new PVECurrent(_client, _node, _vmid);
                            }
                            return _current;
                        }
                        private PVEStart _start;

                        public PVEStart getStart() {
                            if (_start == null) {
                                _start = new PVEStart(_client, _node, _vmid);
                            }
                            return _start;
                        }
                        private PVEStop _stop;

                        public PVEStop getStop() {
                            if (_stop == null) {
                                _stop = new PVEStop(_client, _node, _vmid);
                            }
                            return _stop;
                        }
                        private PVEReset _reset;

                        public PVEReset getReset() {
                            if (_reset == null) {
                                _reset = new PVEReset(_client, _node, _vmid);
                            }
                            return _reset;
                        }
                        private PVEShutdown _shutdown;

                        public PVEShutdown getShutdown() {
                            if (_shutdown == null) {
                                _shutdown = new PVEShutdown(_client, _node, _vmid);
                            }
                            return _shutdown;
                        }
                        private PVESuspend _suspend;

                        public PVESuspend getSuspend() {
                            if (_suspend == null) {
                                _suspend = new PVESuspend(_client, _node, _vmid);
                            }
                            return _suspend;
                        }
                        private PVEResume _resume;

                        public PVEResume getResume() {
                            if (_resume == null) {
                                _resume = new PVEResume(_client, _node, _vmid);
                            }
                            return _resume;
                        }

                        public class PVECurrent extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVECurrent(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Get virtual machine status.
                             */
                            public JSONObject vmStatus() throws JSONException {
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/status/current", null);
                            }
                        }

                        public class PVEStart extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEStart(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Start virtual machine.
                             *
                             * @param machine Specific the Qemu machine type.
                             * @param migratedfrom The cluster node name.
                             * @param migration_network CIDR of the (sub)
                             * network that is used for migration.
                             * @param migration_type Migration traffic is
                             * encrypted using an SSH tunnel by default. On
                             * secure, completely private networks this can be
                             * disabled to increase performance. Enum:
                             * secure,insecure
                             * @param skiplock Ignore locks - only root is
                             * allowed to use this option.
                             * @param stateuri Some command save/restore state
                             * from this location.
                             * @param targetstorage Target storage for the
                             * migration. (Can be '1' to use the same storage id
                             * as on the source node.)
                             */
                            public JSONObject vmStart(String machine, String migratedfrom, String migration_network, String migration_type, Boolean skiplock, String stateuri, String targetstorage) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("machine", machine);
                                parameters.put("migratedfrom", migratedfrom);
                                parameters.put("migration_network", migration_network);
                                parameters.put("migration_type", migration_type);
                                parameters.put("skiplock", skiplock);
                                parameters.put("stateuri", stateuri);
                                parameters.put("targetstorage", targetstorage);
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/start", parameters);
                            }

                            /**
                             * Start virtual machine.
                             */
                            public JSONObject vmStart() throws JSONException {
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/start", null);
                            }
                        }

                        public class PVEStop extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEStop(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Stop virtual machine. The qemu process will exit
                             * immediately. Thisis akin to pulling the power
                             * plug of a running computer and may damage the VM
                             * data
                             *
                             * @param keepActive Do not deactivate storage
                             * volumes.
                             * @param migratedfrom The cluster node name.
                             * @param skiplock Ignore locks - only root is
                             * allowed to use this option.
                             * @param timeout Wait maximal timeout seconds.
                             */
                            public JSONObject vmStop(Boolean keepActive, String migratedfrom, Boolean skiplock, Integer timeout) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("keepActive", keepActive);
                                parameters.put("migratedfrom", migratedfrom);
                                parameters.put("skiplock", skiplock);
                                parameters.put("timeout", timeout);
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/stop", parameters);
                            }

                            /**
                             * Stop virtual machine. The qemu process will exit
                             * immediately. Thisis akin to pulling the power
                             * plug of a running computer and may damage the VM
                             * data
                             */
                            public JSONObject vmStop() throws JSONException {
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/stop", null);
                            }
                        }

                        public class PVEReset extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEReset(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Reset virtual machine.
                             *
                             * @param skiplock Ignore locks - only root is
                             * allowed to use this option.
                             */
                            public JSONObject vmReset(Boolean skiplock) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("skiplock", skiplock);
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/reset", parameters);
                            }

                            /**
                             * Reset virtual machine.
                             */
                            public JSONObject vmReset() throws JSONException {
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/reset", null);
                            }
                        }

                        public class PVEShutdown extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEShutdown(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Shutdown virtual machine. This is similar to
                             * pressing the power button on a physical
                             * machine.This will send an ACPI event for the
                             * guest OS, which should then proceed to a clean
                             * shutdown.
                             *
                             * @param forceStop Make sure the VM stops.
                             * @param keepActive Do not deactivate storage
                             * volumes.
                             * @param skiplock Ignore locks - only root is
                             * allowed to use this option.
                             * @param timeout Wait maximal timeout seconds.
                             */
                            public JSONObject vmShutdown(Boolean forceStop, Boolean keepActive, Boolean skiplock, Integer timeout) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("forceStop", forceStop);
                                parameters.put("keepActive", keepActive);
                                parameters.put("skiplock", skiplock);
                                parameters.put("timeout", timeout);
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/shutdown", parameters);
                            }

                            /**
                             * Shutdown virtual machine. This is similar to
                             * pressing the power button on a physical
                             * machine.This will send an ACPI event for the
                             * guest OS, which should then proceed to a clean
                             * shutdown.
                             */
                            public JSONObject vmShutdown() throws JSONException {
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/shutdown", null);
                            }
                        }

                        public class PVESuspend extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVESuspend(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Suspend virtual machine.
                             *
                             * @param skiplock Ignore locks - only root is
                             * allowed to use this option.
                             */
                            public JSONObject vmSuspend(Boolean skiplock) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("skiplock", skiplock);
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/suspend", parameters);
                            }

                            /**
                             * Suspend virtual machine.
                             */
                            public JSONObject vmSuspend() throws JSONException {
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/suspend", null);
                            }
                        }

                        public class PVEResume extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEResume(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Resume virtual machine.
                             *
                             * @param nocheck
                             * @param skiplock Ignore locks - only root is
                             * allowed to use this option.
                             */
                            public JSONObject vmResume(Boolean nocheck, Boolean skiplock) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("nocheck", nocheck);
                                parameters.put("skiplock", skiplock);
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/resume", parameters);
                            }

                            /**
                             * Resume virtual machine.
                             */
                            public JSONObject vmResume() throws JSONException {
                                return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/status/resume", null);
                            }
                        }

                        /**
                         * Directory index
                         */
                        public JSONObject vmcmdidx() throws JSONException {
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/status", null);
                        }
                    }

                    public class PVESendkey extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVESendkey(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Send key event to virtual machine.
                         *
                         * @param key The key (qemu monitor encoding).
                         * @param skiplock Ignore locks - only root is allowed
                         * to use this option.
                         */
                        public void vmSendkey(String key, Boolean skiplock) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("key", key);
                            parameters.put("skiplock", skiplock);
                            _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/sendkey", parameters);
                        }

                        /**
                         * Send key event to virtual machine.
                         *
                         * @param key The key (qemu monitor encoding).
                         */
                        public void vmSendkey(String key) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("key", key);
                            _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/sendkey", parameters);
                        }
                    }

                    public class PVEFeature extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEFeature(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Check if feature for virtual machine is available.
                         *
                         * @param feature Feature to check. Enum:
                         * snapshot,clone,copy
                         * @param snapname The name of the snapshot.
                         */
                        public JSONObject vmFeature(String feature, String snapname) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("feature", feature);
                            parameters.put("snapname", snapname);
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/feature", parameters);
                        }

                        /**
                         * Check if feature for virtual machine is available.
                         *
                         * @param feature Feature to check. Enum:
                         * snapshot,clone,copy
                         */
                        public JSONObject vmFeature(String feature) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("feature", feature);
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/feature", parameters);
                        }
                    }

                    public class PVEClone extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEClone(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Create a copy of virtual machine/template.
                         *
                         * @param newid VMID for the clone.
                         * @param description Description for the new VM.
                         * @param format Target format for file storage. Enum:
                         * raw,qcow2,vmdk
                         * @param full Create a full copy of all disk. This is
                         * always done when you clone a normal VM. For VM
                         * templates, we try to create a linked clone by
                         * default.
                         * @param name Set a name for the new VM.
                         * @param pool Add the new VM to the specified pool.
                         * @param snapname The name of the snapshot.
                         * @param storage Target storage for full clone.
                         * @param target Target node. Only allowed if the
                         * original VM is on shared storage.
                         */
                        public JSONObject cloneVm(int newid, String description, String format, Boolean full, String name, String pool, String snapname, String storage, String target) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("newid", newid);
                            parameters.put("description", description);
                            parameters.put("format", format);
                            parameters.put("full", full);
                            parameters.put("name", name);
                            parameters.put("pool", pool);
                            parameters.put("snapname", snapname);
                            parameters.put("storage", storage);
                            parameters.put("target", target);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/clone", parameters);
                        }

                        /**
                         * Create a copy of virtual machine/template.
                         *
                         * @param newid VMID for the clone.
                         */
                        public JSONObject cloneVm(int newid) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("newid", newid);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/clone", parameters);
                        }
                    }

                    public class PVEMoveDisk extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEMoveDisk(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Move volume to different storage.
                         *
                         * @param disk The disk you want to move. Enum:
                         * ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0
                         * @param storage Target storage.
                         * @param delete Delete the original disk after
                         * successful copy. By default the original disk is kept
                         * as unused disk.
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         * @param format Target Format. Enum: raw,qcow2,vmdk
                         */
                        public JSONObject moveVmDisk(String disk, String storage, Boolean delete, String digest, String format) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("disk", disk);
                            parameters.put("storage", storage);
                            parameters.put("delete", delete);
                            parameters.put("digest", digest);
                            parameters.put("format", format);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/move_disk", parameters);
                        }

                        /**
                         * Move volume to different storage.
                         *
                         * @param disk The disk you want to move. Enum:
                         * ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0
                         * @param storage Target storage.
                         */
                        public JSONObject moveVmDisk(String disk, String storage) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("disk", disk);
                            parameters.put("storage", storage);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/move_disk", parameters);
                        }
                    }

                    public class PVEMigrate extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEMigrate(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Migrate virtual machine. Creates a new migration
                         * task.
                         *
                         * @param target Target node.
                         * @param force Allow to migrate VMs which use local
                         * devices. Only root may use this option.
                         * @param migration_network CIDR of the (sub) network
                         * that is used for migration.
                         * @param migration_type Migration traffic is encrypted
                         * using an SSH tunnel by default. On secure, completely
                         * private networks this can be disabled to increase
                         * performance. Enum: secure,insecure
                         * @param online Use online/live migration.
                         * @param targetstorage Default target storage.
                         * @param with_local_disks Enable live storage migration
                         * for local disk
                         */
                        public JSONObject migrateVm(String target, Boolean force, String migration_network, String migration_type, Boolean online, String targetstorage, Boolean with_local_disks) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("target", target);
                            parameters.put("force", force);
                            parameters.put("migration_network", migration_network);
                            parameters.put("migration_type", migration_type);
                            parameters.put("online", online);
                            parameters.put("targetstorage", targetstorage);
                            parameters.put("with-local-disks", with_local_disks);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/migrate", parameters);
                        }

                        /**
                         * Migrate virtual machine. Creates a new migration
                         * task.
                         *
                         * @param target Target node.
                         */
                        public JSONObject migrateVm(String target) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("target", target);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/migrate", parameters);
                        }
                    }

                    public class PVEMonitor extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEMonitor(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Execute Qemu monitor commands.
                         *
                         * @param command The monitor command.
                         */
                        public JSONObject monitor(String command) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("command", command);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/monitor", parameters);
                        }
                    }

                    public class PVEAgent extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEAgent(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Execute Qemu Guest Agent commands.
                         *
                         * @param command The QGA command. Enum:
                         * ping,get-time,info,fsfreeze-status,fsfreeze-freeze,fsfreeze-thaw,fstrim,network-get-interfaces,get-vcpus,get-fsinfo,get-memory-blocks,get-memory-block-info,suspend-hybrid,suspend-ram,suspend-disk,shutdown
                         */
                        public JSONObject agent(String command) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("command", command);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/agent", parameters);
                        }
                    }

                    public class PVEResize extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEResize(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Extend volume size.
                         *
                         * @param disk The disk you want to resize. Enum:
                         * ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0
                         * @param size The new size. With the `+` sign the value
                         * is added to the actual size of the volume and without
                         * it, the value is taken as an absolute one. Shrinking
                         * disk size is not supported.
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         * @param skiplock Ignore locks - only root is allowed
                         * to use this option.
                         */
                        public void resizeVm(String disk, String size, String digest, Boolean skiplock) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("disk", disk);
                            parameters.put("size", size);
                            parameters.put("digest", digest);
                            parameters.put("skiplock", skiplock);
                            _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/resize", parameters);
                        }

                        /**
                         * Extend volume size.
                         *
                         * @param disk The disk you want to resize. Enum:
                         * ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0
                         * @param size The new size. With the `+` sign the value
                         * is added to the actual size of the volume and without
                         * it, the value is taken as an absolute one. Shrinking
                         * disk size is not supported.
                         */
                        public void resizeVm(String disk, String size) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("disk", disk);
                            parameters.put("size", size);
                            _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/resize", parameters);
                        }
                    }

                    public class PVESnapshot extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVESnapshot(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        public PVEItemSnapname get(Object snapname) {
                            return new PVEItemSnapname(_client, _node, _vmid, snapname);
                        }

                        public class PVEItemSnapname extends Base {

                            private Object _node;
                            private Object _vmid;
                            private Object _snapname;

                            protected PVEItemSnapname(Client client, Object node, Object vmid, Object snapname) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                                _snapname = snapname;
                            }
                            private PVEConfig _config;

                            public PVEConfig getConfig() {
                                if (_config == null) {
                                    _config = new PVEConfig(_client, _node, _vmid, _snapname);
                                }
                                return _config;
                            }
                            private PVERollback _rollback;

                            public PVERollback getRollback() {
                                if (_rollback == null) {
                                    _rollback = new PVERollback(_client, _node, _vmid, _snapname);
                                }
                                return _rollback;
                            }

                            public class PVEConfig extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _snapname;

                                protected PVEConfig(Client client, Object node, Object vmid, Object snapname) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _snapname = snapname;
                                }

                                /**
                                 * Get snapshot configuration
                                 */
                                public JSONObject getSnapshotConfig() throws JSONException {
                                    return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot/" + _snapname + "/config", null);
                                }

                                /**
                                 * Update snapshot metadata.
                                 *
                                 * @param description A textual description or
                                 * comment.
                                 */
                                public void updateSnapshotConfig(String description) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("description", description);
                                    _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot/" + _snapname + "/config", parameters);
                                }

                                /**
                                 * Update snapshot metadata.
                                 */
                                public void updateSnapshotConfig() throws JSONException {
                                    _client.put("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot/" + _snapname + "/config", null);
                                }
                            }

                            public class PVERollback extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _snapname;

                                protected PVERollback(Client client, Object node, Object vmid, Object snapname) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _snapname = snapname;
                                }

                                /**
                                 * Rollback VM state to specified snapshot.
                                 */
                                public JSONObject rollback() throws JSONException {
                                    return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot/" + _snapname + "/rollback", null);
                                }
                            }

                            /**
                             * Delete a VM snapshot.
                             *
                             * @param force For removal from config file, even
                             * if removing disk snapshots fails.
                             */
                            public JSONObject delsnapshot(Boolean force) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("force", force);
                                return _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot/" + _snapname + "", parameters);
                            }

                            /**
                             * Delete a VM snapshot.
                             */
                            public JSONObject delsnapshot() throws JSONException {
                                return _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot/" + _snapname + "", null);
                            }

                            /**
                             *
                             */
                            public JSONObject snapshotCmdIdx() throws JSONException {
                                return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot/" + _snapname + "", null);
                            }
                        }

                        /**
                         * List all snapshots.
                         */
                        public JSONObject snapshotList() throws JSONException {
                            return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot", null);
                        }

                        /**
                         * Snapshot a VM.
                         *
                         * @param snapname The name of the snapshot.
                         * @param description A textual description or comment.
                         * @param vmstate Save the vmstate
                         */
                        public JSONObject snapshot(String snapname, String description, Boolean vmstate) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("snapname", snapname);
                            parameters.put("description", description);
                            parameters.put("vmstate", vmstate);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot", parameters);
                        }

                        /**
                         * Snapshot a VM.
                         *
                         * @param snapname The name of the snapshot.
                         */
                        public JSONObject snapshot(String snapname) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("snapname", snapname);
                            return _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/snapshot", parameters);
                        }
                    }

                    public class PVETemplate extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVETemplate(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Create a Template.
                         *
                         * @param disk If you want to convert only 1 disk to
                         * base image. Enum:
                         * ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0
                         */
                        public void template(String disk) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("disk", disk);
                            _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/template", parameters);
                        }

                        /**
                         * Create a Template.
                         */
                        public void template() throws JSONException {
                            _client.post("/nodes/" + _node + "/qemu/" + _vmid + "/template", null);
                        }
                    }

                    /**
                     * Destroy the vm (also delete all used/owned volumes).
                     *
                     * @param skiplock Ignore locks - only root is allowed to
                     * use this option.
                     */
                    public JSONObject destroyVm(Boolean skiplock) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("skiplock", skiplock);
                        return _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "", parameters);
                    }

                    /**
                     * Destroy the vm (also delete all used/owned volumes).
                     */
                    public JSONObject destroyVm() throws JSONException {
                        return _client.delete("/nodes/" + _node + "/qemu/" + _vmid + "", null);
                    }

                    /**
                     * Directory index
                     */
                    public JSONObject vmdiridx() throws JSONException {
                        return _client.get("/nodes/" + _node + "/qemu/" + _vmid + "", null);
                    }
                }

                /**
                 * Virtual machine index (per node).
                 *
                 * @param full Determine the full status of active VMs.
                 */
                public JSONObject vmlist(Boolean full) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("full", full);
                    return _client.get("/nodes/" + _node + "/qemu", parameters);
                }

                /**
                 * Virtual machine index (per node).
                 */
                public JSONObject vmlist() throws JSONException {
                    return _client.get("/nodes/" + _node + "/qemu", null);
                }

                /**
                 * Create or restore a virtual machine.
                 *
                 * @param vmid The (unique) ID of the VM.
                 * @param acpi Enable/disable ACPI.
                 * @param agent Enable/disable Qemu GuestAgent.
                 * @param archive The backup file.
                 * @param args Arbitrary arguments passed to kvm.
                 * @param autostart Automatic restart after crash (currently
                 * ignored).
                 * @param balloon Amount of target RAM for the VM in MB. Using
                 * zero disables the ballon driver.
                 * @param bios Select BIOS implementation. Enum: seabios,ovmf
                 * @param boot Boot on floppy (a), hard disk (c), CD-ROM (d), or
                 * network (n).
                 * @param bootdisk Enable booting from specified disk.
                 * @param cdrom This is an alias for option -ide2
                 * @param cores The number of cores per socket.
                 * @param cpu Emulated CPU type.
                 * @param cpulimit Limit of CPU usage.
                 * @param cpuunits CPU weight for a VM.
                 * @param description Description for the VM. Only used on the
                 * configuration web interface. This is saved as comment inside
                 * the configuration file.
                 * @param force Allow to overwrite existing VM.
                 * @param freeze Freeze CPU at startup (use 'c' monitor command
                 * to start execution).
                 * @param hostpciN Map host PCI devices into guest.
                 * @param hotplug Selectively enable hotplug features. This is a
                 * comma separated list of hotplug features: 'network', 'disk',
                 * 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug
                 * completely. Value '1' is an alias for the default
                 * 'network,disk,usb'.
                 * @param hugepages Enable/disable hugepages memory. Enum:
                 * any,2,1024
                 * @param ideN Use volume as IDE hard disk or CD-ROM (n is 0 to
                 * 3).
                 * @param keyboard Keybord layout for vnc server. Default is
                 * read from the '/etc/pve/datacenter.conf' configuration file.
                 * Enum:
                 * de,de-ch,da,en-gb,en-us,es,fi,fr,fr-be,fr-ca,fr-ch,hu,is,it,ja,lt,mk,nl,no,pl,pt,pt-br,sv,sl,tr
                 * @param kvm Enable/disable KVM hardware virtualization.
                 * @param localtime Set the real time clock to local time. This
                 * is enabled by default if ostype indicates a Microsoft OS.
                 * @param lock_ Lock/unlock the VM. Enum:
                 * migrate,backup,snapshot,rollback
                 * @param machine Specific the Qemu machine type.
                 * @param memory Amount of RAM for the VM in MB. This is the
                 * maximum available memory when you use the balloon device.
                 * @param migrate_downtime Set maximum tolerated downtime (in
                 * seconds) for migrations.
                 * @param migrate_speed Set maximum speed (in MB/s) for
                 * migrations. Value 0 is no limit.
                 * @param name Set a name for the VM. Only used on the
                 * configuration web interface.
                 * @param netN Specify network devices.
                 * @param numa Enable/disable NUMA.
                 * @param numaN NUMA topology.
                 * @param onboot Specifies whether a VM will be started during
                 * system bootup.
                 * @param ostype Specify guest operating system. Enum:
                 * other,wxp,w2k,w2k3,w2k8,wvista,win7,win8,win10,l24,l26,solaris
                 * @param parallelN Map host parallel devices (n is 0 to 2).
                 * @param pool Add the VM to the specified pool.
                 * @param protection Sets the protection flag of the VM. This
                 * will disable the remove VM and remove disk operations.
                 * @param reboot Allow reboot. If set to '0' the VM exit on
                 * reboot.
                 * @param sataN Use volume as SATA hard disk or CD-ROM (n is 0
                 * to 5).
                 * @param scsiN Use volume as SCSI hard disk or CD-ROM (n is 0
                 * to 13).
                 * @param scsihw SCSI controller model Enum:
                 * lsi,lsi53c810,virtio-scsi-pci,virtio-scsi-single,megasas,pvscsi
                 * @param serialN Create a serial device inside the VM (n is 0
                 * to 3)
                 * @param shares Amount of memory shares for auto-ballooning.
                 * The larger the number is, the more memory this VM gets.
                 * Number is relative to weights of all other running VMs. Using
                 * zero disables auto-ballooning
                 * @param smbios1 Specify SMBIOS type 1 fields.
                 * @param smp The number of CPUs. Please use option -sockets
                 * instead.
                 * @param sockets The number of CPU sockets.
                 * @param startdate Set the initial date of the real time clock.
                 * Valid format for date are: 'now' or '2006-06-17T16:01:21' or
                 * '2006-06-17'.
                 * @param startup Startup and shutdown behavior. Order is a
                 * non-negative number defining the general startup order.
                 * Shutdown in done with reverse ordering. Additionally you can
                 * set the 'up' or 'down' delay in seconds, which specifies a
                 * delay to wait before the next VM is started or stopped.
                 * @param storage Default storage.
                 * @param tablet Enable/disable the USB tablet device.
                 * @param tdf Enable/disable time drift fix.
                 * @param template Enable/disable Template.
                 * @param unique Assign a unique random ethernet address.
                 * @param unusedN Reference to unused volumes. This is used
                 * internally, and should not be modified manually.
                 * @param usbN Configure an USB device (n is 0 to 4).
                 * @param vcpus Number of hotplugged vcpus.
                 * @param vga Select the VGA type. Enum:
                 * std,cirrus,vmware,qxl,serial0,serial1,serial2,serial3,qxl2,qxl3,qxl4
                 * @param virtioN Use volume as VIRTIO hard disk (n is 0 to 15).
                 * @param watchdog Create a virtual hardware watchdog device.
                 */
                public JSONObject createVm(int vmid, Boolean acpi, Boolean agent, String archive, String args, Boolean autostart, Integer balloon, String bios, String boot, String bootdisk, String cdrom, Integer cores, String cpu, Integer cpulimit, Integer cpuunits, String description, Boolean force, Boolean freeze, Map<Integer, String> hostpciN, String hotplug, String hugepages, Map<Integer, String> ideN, String keyboard, Boolean kvm, Boolean localtime, String lock_, String machine, Integer memory, Integer migrate_downtime, Integer migrate_speed, String name, Map<Integer, String> netN, Boolean numa, Map<Integer, String> numaN, Boolean onboot, String ostype, Map<Integer, String> parallelN, String pool, Boolean protection, Boolean reboot, Map<Integer, String> sataN, Map<Integer, String> scsiN, String scsihw, Map<Integer, String> serialN, Integer shares, String smbios1, Integer smp, Integer sockets, String startdate, String startup, String storage, Boolean tablet, Boolean tdf, Boolean template, Boolean unique, Map<Integer, String> unusedN, Map<Integer, String> usbN, Integer vcpus, String vga, Map<Integer, String> virtioN, String watchdog) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("vmid", vmid);
                    parameters.put("acpi", acpi);
                    parameters.put("agent", agent);
                    parameters.put("archive", archive);
                    parameters.put("args", args);
                    parameters.put("autostart", autostart);
                    parameters.put("balloon", balloon);
                    parameters.put("bios", bios);
                    parameters.put("boot", boot);
                    parameters.put("bootdisk", bootdisk);
                    parameters.put("cdrom", cdrom);
                    parameters.put("cores", cores);
                    parameters.put("cpu", cpu);
                    parameters.put("cpulimit", cpulimit);
                    parameters.put("cpuunits", cpuunits);
                    parameters.put("description", description);
                    parameters.put("force", force);
                    parameters.put("freeze", freeze);
                    parameters.put("hotplug", hotplug);
                    parameters.put("hugepages", hugepages);
                    parameters.put("keyboard", keyboard);
                    parameters.put("kvm", kvm);
                    parameters.put("localtime", localtime);
                    parameters.put("lock", lock_);
                    parameters.put("machine", machine);
                    parameters.put("memory", memory);
                    parameters.put("migrate_downtime", migrate_downtime);
                    parameters.put("migrate_speed", migrate_speed);
                    parameters.put("name", name);
                    parameters.put("numa", numa);
                    parameters.put("onboot", onboot);
                    parameters.put("ostype", ostype);
                    parameters.put("pool", pool);
                    parameters.put("protection", protection);
                    parameters.put("reboot", reboot);
                    parameters.put("scsihw", scsihw);
                    parameters.put("shares", shares);
                    parameters.put("smbios1", smbios1);
                    parameters.put("smp", smp);
                    parameters.put("sockets", sockets);
                    parameters.put("startdate", startdate);
                    parameters.put("startup", startup);
                    parameters.put("storage", storage);
                    parameters.put("tablet", tablet);
                    parameters.put("tdf", tdf);
                    parameters.put("template", template);
                    parameters.put("unique", unique);
                    parameters.put("vcpus", vcpus);
                    parameters.put("vga", vga);
                    parameters.put("watchdog", watchdog);
                    addIndexedParmeter(parameters, "hostpci", hostpciN);
                    addIndexedParmeter(parameters, "ide", ideN);
                    addIndexedParmeter(parameters, "net", netN);
                    addIndexedParmeter(parameters, "numa", numaN);
                    addIndexedParmeter(parameters, "parallel", parallelN);
                    addIndexedParmeter(parameters, "sata", sataN);
                    addIndexedParmeter(parameters, "scsi", scsiN);
                    addIndexedParmeter(parameters, "serial", serialN);
                    addIndexedParmeter(parameters, "unused", unusedN);
                    addIndexedParmeter(parameters, "usb", usbN);
                    addIndexedParmeter(parameters, "virtio", virtioN);
                    return _client.post("/nodes/" + _node + "/qemu", parameters);
                }

                /**
                 * Create or restore a virtual machine.
                 *
                 * @param vmid The (unique) ID of the VM.
                 */
                public JSONObject createVm(int vmid) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("vmid", vmid);
                    return _client.post("/nodes/" + _node + "/qemu", parameters);
                }
            }

            public class PVELxc extends Base {

                private Object _node;

                protected PVELxc(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                public PVEItemVmid get(Object vmid) {
                    return new PVEItemVmid(_client, _node, vmid);
                }

                public class PVEItemVmid extends Base {

                    private Object _node;
                    private Object _vmid;

                    protected PVEItemVmid(Client client, Object node, Object vmid) {
                        _client = client;
                        _node = node;
                        _vmid = vmid;
                    }
                    private PVEConfig _config;

                    public PVEConfig getConfig() {
                        if (_config == null) {
                            _config = new PVEConfig(_client, _node, _vmid);
                        }
                        return _config;
                    }
                    private PVEStatus _status;

                    public PVEStatus getStatus() {
                        if (_status == null) {
                            _status = new PVEStatus(_client, _node, _vmid);
                        }
                        return _status;
                    }
                    private PVESnapshot _snapshot;

                    public PVESnapshot getSnapshot() {
                        if (_snapshot == null) {
                            _snapshot = new PVESnapshot(_client, _node, _vmid);
                        }
                        return _snapshot;
                    }
                    private PVEFirewall _firewall;

                    public PVEFirewall getFirewall() {
                        if (_firewall == null) {
                            _firewall = new PVEFirewall(_client, _node, _vmid);
                        }
                        return _firewall;
                    }
                    private PVERrd _rrd;

                    public PVERrd getRrd() {
                        if (_rrd == null) {
                            _rrd = new PVERrd(_client, _node, _vmid);
                        }
                        return _rrd;
                    }
                    private PVERrddata _rrddata;

                    public PVERrddata getRrddata() {
                        if (_rrddata == null) {
                            _rrddata = new PVERrddata(_client, _node, _vmid);
                        }
                        return _rrddata;
                    }
                    private PVEVncproxy _vncproxy;

                    public PVEVncproxy getVncproxy() {
                        if (_vncproxy == null) {
                            _vncproxy = new PVEVncproxy(_client, _node, _vmid);
                        }
                        return _vncproxy;
                    }
                    private PVEVncwebsocket _vncwebsocket;

                    public PVEVncwebsocket getVncwebsocket() {
                        if (_vncwebsocket == null) {
                            _vncwebsocket = new PVEVncwebsocket(_client, _node, _vmid);
                        }
                        return _vncwebsocket;
                    }
                    private PVESpiceproxy _spiceproxy;

                    public PVESpiceproxy getSpiceproxy() {
                        if (_spiceproxy == null) {
                            _spiceproxy = new PVESpiceproxy(_client, _node, _vmid);
                        }
                        return _spiceproxy;
                    }
                    private PVEMigrate _migrate;

                    public PVEMigrate getMigrate() {
                        if (_migrate == null) {
                            _migrate = new PVEMigrate(_client, _node, _vmid);
                        }
                        return _migrate;
                    }
                    private PVEFeature _feature;

                    public PVEFeature getFeature() {
                        if (_feature == null) {
                            _feature = new PVEFeature(_client, _node, _vmid);
                        }
                        return _feature;
                    }
                    private PVETemplate _template;

                    public PVETemplate getTemplate() {
                        if (_template == null) {
                            _template = new PVETemplate(_client, _node, _vmid);
                        }
                        return _template;
                    }
                    private PVEClone _clone;

                    public PVEClone getClone() {
                        if (_clone == null) {
                            _clone = new PVEClone(_client, _node, _vmid);
                        }
                        return _clone;
                    }
                    private PVEResize _resize;

                    public PVEResize getResize() {
                        if (_resize == null) {
                            _resize = new PVEResize(_client, _node, _vmid);
                        }
                        return _resize;
                    }

                    public class PVEConfig extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEConfig(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Get container configuration.
                         */
                        public JSONObject vmConfig() throws JSONException {
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/config", null);
                        }

                        /**
                         * Set container options.
                         *
                         * @param arch OS architecture type. Enum: amd64,i386
                         * @param cmode Console mode. By default, the console
                         * command tries to open a connection to one of the
                         * available tty devices. By setting cmode to 'console'
                         * it tries to attach to /dev/console instead. If you
                         * set cmode to 'shell', it simply invokes a shell
                         * inside the container (no login). Enum:
                         * shell,console,tty
                         * @param console Attach a console device (/dev/console)
                         * to the container.
                         * @param cores The number of cores assigned to the
                         * container. A container can use all available cores by
                         * default.
                         * @param cpulimit Limit of CPU usage. NOTE: If the
                         * computer has 2 CPUs, it has a total of '2' CPU time.
                         * Value '0' indicates no CPU limit.
                         * @param cpuunits CPU weight for a VM. Argument is used
                         * in the kernel fair scheduler. The larger the number
                         * is, the more CPU time this VM gets. Number is
                         * relative to the weights of all the other running VMs.
                         * NOTE: You can disable fair-scheduler configuration by
                         * setting this to 0.
                         * @param delete A list of settings you want to delete.
                         * @param description Container description. Only used
                         * on the configuration web interface.
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         * @param hostname Set a host name for the container.
                         * @param lock_ Lock/unlock the VM. Enum:
                         * migrate,backup,snapshot,rollback
                         * @param memory Amount of RAM for the VM in MB.
                         * @param mpN Use volume as container mount point.
                         * @param nameserver Sets DNS server IP address for a
                         * container. Create will automatically use the setting
                         * from the host if you neither set searchdomain nor
                         * nameserver.
                         * @param netN Specifies network interfaces for the
                         * container.
                         * @param onboot Specifies whether a VM will be started
                         * during system bootup.
                         * @param ostype OS type. This is used to setup
                         * configuration inside the container, and corresponds
                         * to lxc setup scripts in
                         * /usr/share/lxc/config/&amp;lt;ostype&amp;gt;.common.conf.
                         * Value 'unmanaged' can be used to skip and OS specific
                         * setup. Enum:
                         * debian,ubuntu,centos,fedora,opensuse,archlinux,alpine,gentoo,unmanaged
                         * @param protection Sets the protection flag of the
                         * container. This will prevent the CT or CT's disk
                         * remove/update operation.
                         * @param rootfs Use volume as container root.
                         * @param searchdomain Sets DNS search domains for a
                         * container. Create will automatically use the setting
                         * from the host if you neither set searchdomain nor
                         * nameserver.
                         * @param startup Startup and shutdown behavior. Order
                         * is a non-negative number defining the general startup
                         * order. Shutdown in done with reverse ordering.
                         * Additionally you can set the 'up' or 'down' delay in
                         * seconds, which specifies a delay to wait before the
                         * next VM is started or stopped.
                         * @param swap Amount of SWAP for the VM in MB.
                         * @param template Enable/disable Template.
                         * @param tty Specify the number of tty available to the
                         * container
                         * @param unprivileged Makes the container run as
                         * unprivileged user. (Should not be modified manually.)
                         * @param unusedN Reference to unused volumes. This is
                         * used internally, and should not be modified manually.
                         */
                        public void updateVm(String arch, String cmode, Boolean console, Integer cores, Integer cpulimit, Integer cpuunits, String delete, String description, String digest, String hostname, String lock_, Integer memory, Map<Integer, String> mpN, String nameserver, Map<Integer, String> netN, Boolean onboot, String ostype, Boolean protection, String rootfs, String searchdomain, String startup, Integer swap, Boolean template, Integer tty, Boolean unprivileged, Map<Integer, String> unusedN) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("arch", arch);
                            parameters.put("cmode", cmode);
                            parameters.put("console", console);
                            parameters.put("cores", cores);
                            parameters.put("cpulimit", cpulimit);
                            parameters.put("cpuunits", cpuunits);
                            parameters.put("delete", delete);
                            parameters.put("description", description);
                            parameters.put("digest", digest);
                            parameters.put("hostname", hostname);
                            parameters.put("lock", lock_);
                            parameters.put("memory", memory);
                            parameters.put("nameserver", nameserver);
                            parameters.put("onboot", onboot);
                            parameters.put("ostype", ostype);
                            parameters.put("protection", protection);
                            parameters.put("rootfs", rootfs);
                            parameters.put("searchdomain", searchdomain);
                            parameters.put("startup", startup);
                            parameters.put("swap", swap);
                            parameters.put("template", template);
                            parameters.put("tty", tty);
                            parameters.put("unprivileged", unprivileged);
                            addIndexedParmeter(parameters, "mp", mpN);
                            addIndexedParmeter(parameters, "net", netN);
                            addIndexedParmeter(parameters, "unused", unusedN);
                            _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/config", parameters);
                        }

                        /**
                         * Set container options.
                         */
                        public void updateVm() throws JSONException {
                            _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/config", null);
                        }
                    }

                    public class PVEStatus extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEStatus(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }
                        private PVECurrent _current;

                        public PVECurrent getCurrent() {
                            if (_current == null) {
                                _current = new PVECurrent(_client, _node, _vmid);
                            }
                            return _current;
                        }
                        private PVEStart _start;

                        public PVEStart getStart() {
                            if (_start == null) {
                                _start = new PVEStart(_client, _node, _vmid);
                            }
                            return _start;
                        }
                        private PVEStop _stop;

                        public PVEStop getStop() {
                            if (_stop == null) {
                                _stop = new PVEStop(_client, _node, _vmid);
                            }
                            return _stop;
                        }
                        private PVEShutdown _shutdown;

                        public PVEShutdown getShutdown() {
                            if (_shutdown == null) {
                                _shutdown = new PVEShutdown(_client, _node, _vmid);
                            }
                            return _shutdown;
                        }
                        private PVESuspend _suspend;

                        public PVESuspend getSuspend() {
                            if (_suspend == null) {
                                _suspend = new PVESuspend(_client, _node, _vmid);
                            }
                            return _suspend;
                        }
                        private PVEResume _resume;

                        public PVEResume getResume() {
                            if (_resume == null) {
                                _resume = new PVEResume(_client, _node, _vmid);
                            }
                            return _resume;
                        }

                        public class PVECurrent extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVECurrent(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Get virtual machine status.
                             */
                            public JSONObject vmStatus() throws JSONException {
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/status/current", null);
                            }
                        }

                        public class PVEStart extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEStart(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Start the container.
                             *
                             * @param skiplock Ignore locks - only root is
                             * allowed to use this option.
                             */
                            public JSONObject vmStart(Boolean skiplock) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("skiplock", skiplock);
                                return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/status/start", parameters);
                            }

                            /**
                             * Start the container.
                             */
                            public JSONObject vmStart() throws JSONException {
                                return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/status/start", null);
                            }
                        }

                        public class PVEStop extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEStop(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Stop the container. This will abruptly stop all
                             * processes running in the container.
                             *
                             * @param skiplock Ignore locks - only root is
                             * allowed to use this option.
                             */
                            public JSONObject vmStop(Boolean skiplock) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("skiplock", skiplock);
                                return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/status/stop", parameters);
                            }

                            /**
                             * Stop the container. This will abruptly stop all
                             * processes running in the container.
                             */
                            public JSONObject vmStop() throws JSONException {
                                return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/status/stop", null);
                            }
                        }

                        public class PVEShutdown extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEShutdown(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Shutdown the container. This will trigger a clean
                             * shutdown of the container, see lxc-stop(1) for
                             * details.
                             *
                             * @param forceStop Make sure the Container stops.
                             * @param timeout Wait maximal timeout seconds.
                             */
                            public JSONObject vmShutdown(Boolean forceStop, Integer timeout) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("forceStop", forceStop);
                                parameters.put("timeout", timeout);
                                return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/status/shutdown", parameters);
                            }

                            /**
                             * Shutdown the container. This will trigger a clean
                             * shutdown of the container, see lxc-stop(1) for
                             * details.
                             */
                            public JSONObject vmShutdown() throws JSONException {
                                return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/status/shutdown", null);
                            }
                        }

                        public class PVESuspend extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVESuspend(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Suspend the container.
                             */
                            public JSONObject vmSuspend() throws JSONException {
                                return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/status/suspend", null);
                            }
                        }

                        public class PVEResume extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEResume(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Resume the container.
                             */
                            public JSONObject vmResume() throws JSONException {
                                return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/status/resume", null);
                            }
                        }

                        /**
                         * Directory index
                         */
                        public JSONObject vmcmdidx() throws JSONException {
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/status", null);
                        }
                    }

                    public class PVESnapshot extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVESnapshot(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        public PVEItemSnapname get(Object snapname) {
                            return new PVEItemSnapname(_client, _node, _vmid, snapname);
                        }

                        public class PVEItemSnapname extends Base {

                            private Object _node;
                            private Object _vmid;
                            private Object _snapname;

                            protected PVEItemSnapname(Client client, Object node, Object vmid, Object snapname) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                                _snapname = snapname;
                            }
                            private PVERollback _rollback;

                            public PVERollback getRollback() {
                                if (_rollback == null) {
                                    _rollback = new PVERollback(_client, _node, _vmid, _snapname);
                                }
                                return _rollback;
                            }
                            private PVEConfig _config;

                            public PVEConfig getConfig() {
                                if (_config == null) {
                                    _config = new PVEConfig(_client, _node, _vmid, _snapname);
                                }
                                return _config;
                            }

                            public class PVERollback extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _snapname;

                                protected PVERollback(Client client, Object node, Object vmid, Object snapname) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _snapname = snapname;
                                }

                                /**
                                 * Rollback LXC state to specified snapshot.
                                 */
                                public JSONObject rollback() throws JSONException {
                                    return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot/" + _snapname + "/rollback", null);
                                }
                            }

                            public class PVEConfig extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _snapname;

                                protected PVEConfig(Client client, Object node, Object vmid, Object snapname) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _snapname = snapname;
                                }

                                /**
                                 * Get snapshot configuration
                                 */
                                public JSONObject getSnapshotConfig() throws JSONException {
                                    return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot/" + _snapname + "/config", null);
                                }

                                /**
                                 * Update snapshot metadata.
                                 *
                                 * @param description A textual description or
                                 * comment.
                                 */
                                public void updateSnapshotConfig(String description) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("description", description);
                                    _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot/" + _snapname + "/config", parameters);
                                }

                                /**
                                 * Update snapshot metadata.
                                 */
                                public void updateSnapshotConfig() throws JSONException {
                                    _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot/" + _snapname + "/config", null);
                                }
                            }

                            /**
                             * Delete a LXC snapshot.
                             *
                             * @param force For removal from config file, even
                             * if removing disk snapshots fails.
                             */
                            public JSONObject delsnapshot(Boolean force) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("force", force);
                                return _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot/" + _snapname + "", parameters);
                            }

                            /**
                             * Delete a LXC snapshot.
                             */
                            public JSONObject delsnapshot() throws JSONException {
                                return _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot/" + _snapname + "", null);
                            }

                            /**
                             *
                             */
                            public JSONObject snapshotCmdIdx() throws JSONException {
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot/" + _snapname + "", null);
                            }
                        }

                        /**
                         * List all snapshots.
                         */
                        public JSONObject list() throws JSONException {
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot", null);
                        }

                        /**
                         * Snapshot a container.
                         *
                         * @param snapname The name of the snapshot.
                         * @param description A textual description or comment.
                         */
                        public JSONObject snapshot(String snapname, String description) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("snapname", snapname);
                            parameters.put("description", description);
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot", parameters);
                        }

                        /**
                         * Snapshot a container.
                         *
                         * @param snapname The name of the snapshot.
                         */
                        public JSONObject snapshot(String snapname) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("snapname", snapname);
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/snapshot", parameters);
                        }
                    }

                    public class PVEFirewall extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEFirewall(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }
                        private PVERules _rules;

                        public PVERules getRules() {
                            if (_rules == null) {
                                _rules = new PVERules(_client, _node, _vmid);
                            }
                            return _rules;
                        }
                        private PVEAliases _aliases;

                        public PVEAliases getAliases() {
                            if (_aliases == null) {
                                _aliases = new PVEAliases(_client, _node, _vmid);
                            }
                            return _aliases;
                        }
                        private PVEIpset _ipset;

                        public PVEIpset getIpset() {
                            if (_ipset == null) {
                                _ipset = new PVEIpset(_client, _node, _vmid);
                            }
                            return _ipset;
                        }
                        private PVEOptions _options;

                        public PVEOptions getOptions() {
                            if (_options == null) {
                                _options = new PVEOptions(_client, _node, _vmid);
                            }
                            return _options;
                        }
                        private PVELog _log;

                        public PVELog getLog() {
                            if (_log == null) {
                                _log = new PVELog(_client, _node, _vmid);
                            }
                            return _log;
                        }
                        private PVERefs _refs;

                        public PVERefs getRefs() {
                            if (_refs == null) {
                                _refs = new PVERefs(_client, _node, _vmid);
                            }
                            return _refs;
                        }

                        public class PVERules extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVERules(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            public PVEItemPos get(Object pos) {
                                return new PVEItemPos(_client, _node, _vmid, pos);
                            }

                            public class PVEItemPos extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _pos;

                                protected PVEItemPos(Client client, Object node, Object vmid, Object pos) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _pos = pos;
                                }

                                /**
                                 * Delete rule.
                                 *
                                 * @param digest Prevent changes if current
                                 * configuration file has different SHA1 digest.
                                 * This can be used to prevent concurrent
                                 * modifications.
                                 */
                                public void deleteRule(String digest) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("digest", digest);
                                    _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/rules/" + _pos + "", parameters);
                                }

                                /**
                                 * Delete rule.
                                 */
                                public void deleteRule() throws JSONException {
                                    _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/rules/" + _pos + "", null);
                                }

                                /**
                                 * Get single rule data.
                                 */
                                public JSONObject getRule() throws JSONException {
                                    return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/rules/" + _pos + "", null);
                                }

                                /**
                                 * Modify rule data.
                                 *
                                 * @param action Rule action ('ACCEPT', 'DROP',
                                 * 'REJECT') or security group name.
                                 * @param comment Descriptive comment.
                                 * @param delete A list of settings you want to
                                 * delete.
                                 * @param dest Restrict packet destination
                                 * address. This can refer to a single IP
                                 * address, an IP set ('+ipsetname') or an IP
                                 * alias definition. You can also specify an
                                 * address range like
                                 * '20.34.101.207-201.3.9.99', or a list of IP
                                 * addresses and networks (entries are separated
                                 * by comma). Please do not mix IPv4 and IPv6
                                 * addresses inside such lists.
                                 * @param digest Prevent changes if current
                                 * configuration file has different SHA1 digest.
                                 * This can be used to prevent concurrent
                                 * modifications.
                                 * @param dport Restrict TCP/UDP destination
                                 * port. You can use service names or simple
                                 * numbers (0-65535), as defined in
                                 * '/etc/services'. Port ranges can be specified
                                 * with '\d+:\d+', for example '80:85', and you
                                 * can use comma separated list to match several
                                 * ports or ranges.
                                 * @param enable Flag to enable/disable a rule.
                                 * @param iface Network interface name. You have
                                 * to use network configuration key names for
                                 * VMs and containers ('net\d+'). Host related
                                 * rules can use arbitrary strings.
                                 * @param macro Use predefined standard macro.
                                 * @param moveto Move rule to new position
                                 * &amp;lt;moveto&amp;gt;. Other arguments are
                                 * ignored.
                                 * @param proto IP protocol. You can use
                                 * protocol names ('tcp'/'udp') or simple
                                 * numbers, as defined in '/etc/protocols'.
                                 * @param source Restrict packet source address.
                                 * This can refer to a single IP address, an IP
                                 * set ('+ipsetname') or an IP alias definition.
                                 * You can also specify an address range like
                                 * '20.34.101.207-201.3.9.99', or a list of IP
                                 * addresses and networks (entries are separated
                                 * by comma). Please do not mix IPv4 and IPv6
                                 * addresses inside such lists.
                                 * @param sport Restrict TCP/UDP source port.
                                 * You can use service names or simple numbers
                                 * (0-65535), as defined in '/etc/services'.
                                 * Port ranges can be specified with '\d+:\d+',
                                 * for example '80:85', and you can use comma
                                 * separated list to match several ports or
                                 * ranges.
                                 * @param type Rule type. Enum: in,out,group
                                 */
                                public void updateRule(String action, String comment, String delete, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer moveto, String proto, String source, String sport, String type) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("action", action);
                                    parameters.put("comment", comment);
                                    parameters.put("delete", delete);
                                    parameters.put("dest", dest);
                                    parameters.put("digest", digest);
                                    parameters.put("dport", dport);
                                    parameters.put("enable", enable);
                                    parameters.put("iface", iface);
                                    parameters.put("macro", macro);
                                    parameters.put("moveto", moveto);
                                    parameters.put("proto", proto);
                                    parameters.put("source", source);
                                    parameters.put("sport", sport);
                                    parameters.put("type", type);
                                    _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/rules/" + _pos + "", parameters);
                                }

                                /**
                                 * Modify rule data.
                                 */
                                public void updateRule() throws JSONException {
                                    _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/rules/" + _pos + "", null);
                                }
                            }

                            /**
                             * List rules.
                             */
                            public JSONObject getRules() throws JSONException {
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/rules", null);
                            }

                            /**
                             * Create new rule.
                             *
                             * @param action Rule action ('ACCEPT', 'DROP',
                             * 'REJECT') or security group name.
                             * @param type Rule type. Enum: in,out,group
                             * @param comment Descriptive comment.
                             * @param dest Restrict packet destination address.
                             * This can refer to a single IP address, an IP set
                             * ('+ipsetname') or an IP alias definition. You can
                             * also specify an address range like
                             * '20.34.101.207-201.3.9.99', or a list of IP
                             * addresses and networks (entries are separated by
                             * comma). Please do not mix IPv4 and IPv6 addresses
                             * inside such lists.
                             * @param digest Prevent changes if current
                             * configuration file has different SHA1 digest.
                             * This can be used to prevent concurrent
                             * modifications.
                             * @param dport Restrict TCP/UDP destination port.
                             * You can use service names or simple numbers
                             * (0-65535), as defined in '/etc/services'. Port
                             * ranges can be specified with '\d+:\d+', for
                             * example '80:85', and you can use comma separated
                             * list to match several ports or ranges.
                             * @param enable Flag to enable/disable a rule.
                             * @param iface Network interface name. You have to
                             * use network configuration key names for VMs and
                             * containers ('net\d+'). Host related rules can use
                             * arbitrary strings.
                             * @param macro Use predefined standard macro.
                             * @param pos Update rule at position
                             * &amp;lt;pos&amp;gt;.
                             * @param proto IP protocol. You can use protocol
                             * names ('tcp'/'udp') or simple numbers, as defined
                             * in '/etc/protocols'.
                             * @param source Restrict packet source address.
                             * This can refer to a single IP address, an IP set
                             * ('+ipsetname') or an IP alias definition. You can
                             * also specify an address range like
                             * '20.34.101.207-201.3.9.99', or a list of IP
                             * addresses and networks (entries are separated by
                             * comma). Please do not mix IPv4 and IPv6 addresses
                             * inside such lists.
                             * @param sport Restrict TCP/UDP source port. You
                             * can use service names or simple numbers
                             * (0-65535), as defined in '/etc/services'. Port
                             * ranges can be specified with '\d+:\d+', for
                             * example '80:85', and you can use comma separated
                             * list to match several ports or ranges.
                             */
                            public void createRule(String action, String type, String comment, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer pos, String proto, String source, String sport) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("action", action);
                                parameters.put("type", type);
                                parameters.put("comment", comment);
                                parameters.put("dest", dest);
                                parameters.put("digest", digest);
                                parameters.put("dport", dport);
                                parameters.put("enable", enable);
                                parameters.put("iface", iface);
                                parameters.put("macro", macro);
                                parameters.put("pos", pos);
                                parameters.put("proto", proto);
                                parameters.put("source", source);
                                parameters.put("sport", sport);
                                _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/rules", parameters);
                            }

                            /**
                             * Create new rule.
                             *
                             * @param action Rule action ('ACCEPT', 'DROP',
                             * 'REJECT') or security group name.
                             * @param type Rule type. Enum: in,out,group
                             */
                            public void createRule(String action, String type) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("action", action);
                                parameters.put("type", type);
                                _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/rules", parameters);
                            }
                        }

                        public class PVEAliases extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEAliases(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            public PVEItemName get(Object name) {
                                return new PVEItemName(_client, _node, _vmid, name);
                            }

                            public class PVEItemName extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _name;

                                protected PVEItemName(Client client, Object node, Object vmid, Object name) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _name = name;
                                }

                                /**
                                 * Remove IP or Network alias.
                                 *
                                 * @param digest Prevent changes if current
                                 * configuration file has different SHA1 digest.
                                 * This can be used to prevent concurrent
                                 * modifications.
                                 */
                                public void removeAlias(String digest) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("digest", digest);
                                    _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/aliases/" + _name + "", parameters);
                                }

                                /**
                                 * Remove IP or Network alias.
                                 */
                                public void removeAlias() throws JSONException {
                                    _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/aliases/" + _name + "", null);
                                }

                                /**
                                 * Read alias.
                                 */
                                public JSONObject readAlias() throws JSONException {
                                    return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/aliases/" + _name + "", null);
                                }

                                /**
                                 * Update IP or Network alias.
                                 *
                                 * @param cidr Network/IP specification in CIDR
                                 * format.
                                 * @param comment
                                 * @param digest Prevent changes if current
                                 * configuration file has different SHA1 digest.
                                 * This can be used to prevent concurrent
                                 * modifications.
                                 * @param rename Rename an existing alias.
                                 */
                                public void updateAlias(String cidr, String comment, String digest, String rename) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("cidr", cidr);
                                    parameters.put("comment", comment);
                                    parameters.put("digest", digest);
                                    parameters.put("rename", rename);
                                    _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/aliases/" + _name + "", parameters);
                                }

                                /**
                                 * Update IP or Network alias.
                                 *
                                 * @param cidr Network/IP specification in CIDR
                                 * format.
                                 */
                                public void updateAlias(String cidr) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("cidr", cidr);
                                    _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/aliases/" + _name + "", parameters);
                                }
                            }

                            /**
                             * List aliases
                             */
                            public JSONObject getAliases() throws JSONException {
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/aliases", null);
                            }

                            /**
                             * Create IP or Network Alias.
                             *
                             * @param cidr Network/IP specification in CIDR
                             * format.
                             * @param name Alias name.
                             * @param comment
                             */
                            public void createAlias(String cidr, String name, String comment) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("cidr", cidr);
                                parameters.put("name", name);
                                parameters.put("comment", comment);
                                _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/aliases", parameters);
                            }

                            /**
                             * Create IP or Network Alias.
                             *
                             * @param cidr Network/IP specification in CIDR
                             * format.
                             * @param name Alias name.
                             */
                            public void createAlias(String cidr, String name) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("cidr", cidr);
                                parameters.put("name", name);
                                _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/aliases", parameters);
                            }
                        }

                        public class PVEIpset extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEIpset(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            public PVEItemName get(Object name) {
                                return new PVEItemName(_client, _node, _vmid, name);
                            }

                            public class PVEItemName extends Base {

                                private Object _node;
                                private Object _vmid;
                                private Object _name;

                                protected PVEItemName(Client client, Object node, Object vmid, Object name) {
                                    _client = client;
                                    _node = node;
                                    _vmid = vmid;
                                    _name = name;
                                }

                                public PVEItemCidr get(Object cidr) {
                                    return new PVEItemCidr(_client, _node, _vmid, _name, cidr);
                                }

                                public class PVEItemCidr extends Base {

                                    private Object _node;
                                    private Object _vmid;
                                    private Object _name;
                                    private Object _cidr;

                                    protected PVEItemCidr(Client client, Object node, Object vmid, Object name, Object cidr) {
                                        _client = client;
                                        _node = node;
                                        _vmid = vmid;
                                        _name = name;
                                        _cidr = cidr;
                                    }

                                    /**
                                     * Remove IP or Network from IPSet.
                                     *
                                     * @param digest Prevent changes if current
                                     * configuration file has different SHA1
                                     * digest. This can be used to prevent
                                     * concurrent modifications.
                                     */
                                    public void removeIp(String digest) throws JSONException {
                                        Map<String, Object> parameters = new HashMap<String, Object>();
                                        parameters.put("digest", digest);
                                        _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", parameters);
                                    }

                                    /**
                                     * Remove IP or Network from IPSet.
                                     */
                                    public void removeIp() throws JSONException {
                                        _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", null);
                                    }

                                    /**
                                     * Read IP or Network settings from IPSet.
                                     */
                                    public JSONObject readIp() throws JSONException {
                                        return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", null);
                                    }

                                    /**
                                     * Update IP or Network settings
                                     *
                                     * @param comment
                                     * @param digest Prevent changes if current
                                     * configuration file has different SHA1
                                     * digest. This can be used to prevent
                                     * concurrent modifications.
                                     * @param nomatch
                                     */
                                    public void updateIp(String comment, String digest, Boolean nomatch) throws JSONException {
                                        Map<String, Object> parameters = new HashMap<String, Object>();
                                        parameters.put("comment", comment);
                                        parameters.put("digest", digest);
                                        parameters.put("nomatch", nomatch);
                                        _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", parameters);
                                    }

                                    /**
                                     * Update IP or Network settings
                                     */
                                    public void updateIp() throws JSONException {
                                        _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "/" + _cidr + "", null);
                                    }
                                }

                                /**
                                 * Delete IPSet
                                 */
                                public void deleteIpset() throws JSONException {
                                    _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "", null);
                                }

                                /**
                                 * List IPSet content
                                 */
                                public JSONObject getIpset() throws JSONException {
                                    return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "", null);
                                }

                                /**
                                 * Add IP or Network to IPSet.
                                 *
                                 * @param cidr Network/IP specification in CIDR
                                 * format.
                                 * @param comment
                                 * @param nomatch
                                 */
                                public void createIp(String cidr, String comment, Boolean nomatch) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("cidr", cidr);
                                    parameters.put("comment", comment);
                                    parameters.put("nomatch", nomatch);
                                    _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "", parameters);
                                }

                                /**
                                 * Add IP or Network to IPSet.
                                 *
                                 * @param cidr Network/IP specification in CIDR
                                 * format.
                                 */
                                public void createIp(String cidr) throws JSONException {
                                    Map<String, Object> parameters = new HashMap<String, Object>();
                                    parameters.put("cidr", cidr);
                                    _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset/" + _name + "", parameters);
                                }
                            }

                            /**
                             * List IPSets
                             */
                            public JSONObject ipsetIndex() throws JSONException {
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset", null);
                            }

                            /**
                             * Create new IPSet
                             *
                             * @param name IP set name.
                             * @param comment
                             * @param digest Prevent changes if current
                             * configuration file has different SHA1 digest.
                             * This can be used to prevent concurrent
                             * modifications.
                             * @param rename Rename an existing IPSet. You can
                             * set 'rename' to the same value as 'name' to
                             * update the 'comment' of an existing IPSet.
                             */
                            public void createIpset(String name, String comment, String digest, String rename) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("name", name);
                                parameters.put("comment", comment);
                                parameters.put("digest", digest);
                                parameters.put("rename", rename);
                                _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset", parameters);
                            }

                            /**
                             * Create new IPSet
                             *
                             * @param name IP set name.
                             */
                            public void createIpset(String name) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("name", name);
                                _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/ipset", parameters);
                            }
                        }

                        public class PVEOptions extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVEOptions(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Get VM firewall options.
                             */
                            public JSONObject getOptions() throws JSONException {
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/options", null);
                            }

                            /**
                             * Set Firewall options.
                             *
                             * @param delete A list of settings you want to
                             * delete.
                             * @param dhcp Enable DHCP.
                             * @param digest Prevent changes if current
                             * configuration file has different SHA1 digest.
                             * This can be used to prevent concurrent
                             * modifications.
                             * @param enable Enable/disable firewall rules.
                             * @param ipfilter Enable default IP filters. This
                             * is equivalent to adding an empty
                             * ipfilter-net&amp;lt;id&amp;gt; ipset for every
                             * interface. Such ipsets implicitly contain sane
                             * default restrictions such as restricting IPv6
                             * link local addresses to the one derived from the
                             * interface's MAC address. For containers the
                             * configured IP addresses will be implicitly added.
                             * @param log_level_in Log level for incoming
                             * traffic. Enum:
                             * emerg,alert,crit,err,warning,notice,info,debug,nolog
                             * @param log_level_out Log level for outgoing
                             * traffic. Enum:
                             * emerg,alert,crit,err,warning,notice,info,debug,nolog
                             * @param macfilter Enable/disable MAC address
                             * filter.
                             * @param ndp Enable NDP.
                             * @param policy_in Input policy. Enum:
                             * ACCEPT,REJECT,DROP
                             * @param policy_out Output policy. Enum:
                             * ACCEPT,REJECT,DROP
                             * @param radv Allow sending Router Advertisement.
                             */
                            public void setOptions(String delete, Boolean dhcp, String digest, Boolean enable, Boolean ipfilter, String log_level_in, String log_level_out, Boolean macfilter, Boolean ndp, String policy_in, String policy_out, Boolean radv) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("delete", delete);
                                parameters.put("dhcp", dhcp);
                                parameters.put("digest", digest);
                                parameters.put("enable", enable);
                                parameters.put("ipfilter", ipfilter);
                                parameters.put("log_level_in", log_level_in);
                                parameters.put("log_level_out", log_level_out);
                                parameters.put("macfilter", macfilter);
                                parameters.put("ndp", ndp);
                                parameters.put("policy_in", policy_in);
                                parameters.put("policy_out", policy_out);
                                parameters.put("radv", radv);
                                _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/options", parameters);
                            }

                            /**
                             * Set Firewall options.
                             */
                            public void setOptions() throws JSONException {
                                _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/options", null);
                            }
                        }

                        public class PVELog extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVELog(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Read firewall log
                             *
                             * @param limit
                             * @param start
                             */
                            public JSONObject log(Integer limit, Integer start) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("limit", limit);
                                parameters.put("start", start);
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/log", parameters);
                            }

                            /**
                             * Read firewall log
                             */
                            public JSONObject log() throws JSONException {
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/log", null);
                            }
                        }

                        public class PVERefs extends Base {

                            private Object _node;
                            private Object _vmid;

                            protected PVERefs(Client client, Object node, Object vmid) {
                                _client = client;
                                _node = node;
                                _vmid = vmid;
                            }

                            /**
                             * Lists possible IPSet/Alias reference which are
                             * allowed in source/dest properties.
                             *
                             * @param type Only list references of specified
                             * type. Enum: alias,ipset
                             */
                            public JSONObject refs(String type) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("type", type);
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/refs", parameters);
                            }

                            /**
                             * Lists possible IPSet/Alias reference which are
                             * allowed in source/dest properties.
                             */
                            public JSONObject refs() throws JSONException {
                                return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall/refs", null);
                            }
                        }

                        /**
                         * Directory index.
                         */
                        public JSONObject index() throws JSONException {
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/firewall", null);
                        }
                    }

                    public class PVERrd extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVERrd(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Read VM RRD statistics (returns PNG)
                         *
                         * @param ds The list of datasources you want to
                         * display.
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         * @param cf The RRD consolidation function Enum:
                         * AVERAGE,MAX
                         */
                        public JSONObject rrd(String ds, String timeframe, String cf) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("ds", ds);
                            parameters.put("timeframe", timeframe);
                            parameters.put("cf", cf);
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/rrd", parameters);
                        }

                        /**
                         * Read VM RRD statistics (returns PNG)
                         *
                         * @param ds The list of datasources you want to
                         * display.
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         */
                        public JSONObject rrd(String ds, String timeframe) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("ds", ds);
                            parameters.put("timeframe", timeframe);
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/rrd", parameters);
                        }
                    }

                    public class PVERrddata extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVERrddata(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Read VM RRD statistics
                         *
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         * @param cf The RRD consolidation function Enum:
                         * AVERAGE,MAX
                         */
                        public JSONObject rrddata(String timeframe, String cf) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("timeframe", timeframe);
                            parameters.put("cf", cf);
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/rrddata", parameters);
                        }

                        /**
                         * Read VM RRD statistics
                         *
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         */
                        public JSONObject rrddata(String timeframe) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("timeframe", timeframe);
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/rrddata", parameters);
                        }
                    }

                    public class PVEVncproxy extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEVncproxy(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Creates a TCP VNC proxy connections.
                         *
                         * @param height sets the height of the console in
                         * pixels.
                         * @param websocket use websocket instead of standard
                         * VNC.
                         * @param width sets the width of the console in pixels.
                         */
                        public JSONObject vncproxy(Integer height, Boolean websocket, Integer width) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("height", height);
                            parameters.put("websocket", websocket);
                            parameters.put("width", width);
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/vncproxy", parameters);
                        }

                        /**
                         * Creates a TCP VNC proxy connections.
                         */
                        public JSONObject vncproxy() throws JSONException {
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/vncproxy", null);
                        }
                    }

                    public class PVEVncwebsocket extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEVncwebsocket(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Opens a weksocket for VNC traffic.
                         *
                         * @param port Port number returned by previous vncproxy
                         * call.
                         * @param vncticket Ticket from previous call to
                         * vncproxy.
                         */
                        public JSONObject vncwebsocket(int port, String vncticket) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("port", port);
                            parameters.put("vncticket", vncticket);
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/vncwebsocket", parameters);
                        }
                    }

                    public class PVESpiceproxy extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVESpiceproxy(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Returns a SPICE configuration to connect to the CT.
                         *
                         * @param proxy SPICE proxy server. This can be used by
                         * the client to specify the proxy server. All nodes in
                         * a cluster runs 'spiceproxy', so it is up to the
                         * client to choose one. By default, we return the node
                         * where the VM is currently running. As resonable
                         * setting is to use same node you use to connect to the
                         * API (This is window.location.hostname for the JS
                         * GUI).
                         */
                        public JSONObject spiceproxy(String proxy) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("proxy", proxy);
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/spiceproxy", parameters);
                        }

                        /**
                         * Returns a SPICE configuration to connect to the CT.
                         */
                        public JSONObject spiceproxy() throws JSONException {
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/spiceproxy", null);
                        }
                    }

                    public class PVEMigrate extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEMigrate(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Migrate the container to another node. Creates a new
                         * migration task.
                         *
                         * @param target Target node.
                         * @param force Force migration despite local bind /
                         * device mounts. NOTE: deprecated, use 'shared'
                         * property of mount point instead.
                         * @param online Use online/live migration.
                         * @param restart Use restart migration
                         * @param timeout Timeout in seconds for shutdown for
                         * restart migration
                         */
                        public JSONObject migrateVm(String target, Boolean force, Boolean online, Boolean restart, Integer timeout) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("target", target);
                            parameters.put("force", force);
                            parameters.put("online", online);
                            parameters.put("restart", restart);
                            parameters.put("timeout", timeout);
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/migrate", parameters);
                        }

                        /**
                         * Migrate the container to another node. Creates a new
                         * migration task.
                         *
                         * @param target Target node.
                         */
                        public JSONObject migrateVm(String target) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("target", target);
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/migrate", parameters);
                        }
                    }

                    public class PVEFeature extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEFeature(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Check if feature for virtual machine is available.
                         *
                         * @param feature Feature to check. Enum: snapshot
                         * @param snapname The name of the snapshot.
                         */
                        public JSONObject vmFeature(String feature, String snapname) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("feature", feature);
                            parameters.put("snapname", snapname);
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/feature", parameters);
                        }

                        /**
                         * Check if feature for virtual machine is available.
                         *
                         * @param feature Feature to check. Enum: snapshot
                         */
                        public JSONObject vmFeature(String feature) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("feature", feature);
                            return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "/feature", parameters);
                        }
                    }

                    public class PVETemplate extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVETemplate(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Create a Template.
                         *
                         * @param experimental The template feature is
                         * experimental, set this flag if you know what you are
                         * doing.
                         */
                        public void template(boolean experimental) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("experimental", experimental);
                            _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/template", parameters);
                        }
                    }

                    public class PVEClone extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEClone(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Create a container clone/copy
                         *
                         * @param experimental The clone feature is
                         * experimental, set this flag if you know what you are
                         * doing.
                         * @param newid VMID for the clone.
                         * @param description Description for the new CT.
                         * @param full Create a full copy of all disk. This is
                         * always done when you clone a normal CT. For CT
                         * templates, we try to create a linked clone by
                         * default.
                         * @param hostname Set a hostname for the new CT.
                         * @param pool Add the new CT to the specified pool.
                         * @param snapname The name of the snapshot.
                         * @param storage Target storage for full clone.
                         */
                        public JSONObject cloneVm(boolean experimental, int newid, String description, Boolean full, String hostname, String pool, String snapname, String storage) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("experimental", experimental);
                            parameters.put("newid", newid);
                            parameters.put("description", description);
                            parameters.put("full", full);
                            parameters.put("hostname", hostname);
                            parameters.put("pool", pool);
                            parameters.put("snapname", snapname);
                            parameters.put("storage", storage);
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/clone", parameters);
                        }

                        /**
                         * Create a container clone/copy
                         *
                         * @param experimental The clone feature is
                         * experimental, set this flag if you know what you are
                         * doing.
                         * @param newid VMID for the clone.
                         */
                        public JSONObject cloneVm(boolean experimental, int newid) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("experimental", experimental);
                            parameters.put("newid", newid);
                            return _client.post("/nodes/" + _node + "/lxc/" + _vmid + "/clone", parameters);
                        }
                    }

                    public class PVEResize extends Base {

                        private Object _node;
                        private Object _vmid;

                        protected PVEResize(Client client, Object node, Object vmid) {
                            _client = client;
                            _node = node;
                            _vmid = vmid;
                        }

                        /**
                         * Resize a container mount point.
                         *
                         * @param disk The disk you want to resize. Enum:
                         * rootfs,mp0,mp1,mp2,mp3,mp4,mp5,mp6,mp7,mp8,mp9
                         * @param size The new size. With the '+' sign the value
                         * is added to the actual size of the volume and without
                         * it, the value is taken as an absolute one. Shrinking
                         * disk size is not supported.
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         */
                        public JSONObject resizeVm(String disk, String size, String digest) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("disk", disk);
                            parameters.put("size", size);
                            parameters.put("digest", digest);
                            return _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/resize", parameters);
                        }

                        /**
                         * Resize a container mount point.
                         *
                         * @param disk The disk you want to resize. Enum:
                         * rootfs,mp0,mp1,mp2,mp3,mp4,mp5,mp6,mp7,mp8,mp9
                         * @param size The new size. With the '+' sign the value
                         * is added to the actual size of the volume and without
                         * it, the value is taken as an absolute one. Shrinking
                         * disk size is not supported.
                         */
                        public JSONObject resizeVm(String disk, String size) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("disk", disk);
                            parameters.put("size", size);
                            return _client.put("/nodes/" + _node + "/lxc/" + _vmid + "/resize", parameters);
                        }
                    }

                    /**
                     * Destroy the container (also delete all uses files).
                     */
                    public JSONObject destroyVm() throws JSONException {
                        return _client.delete("/nodes/" + _node + "/lxc/" + _vmid + "", null);
                    }

                    /**
                     * Directory index
                     */
                    public JSONObject vmdiridx() throws JSONException {
                        return _client.get("/nodes/" + _node + "/lxc/" + _vmid + "", null);
                    }
                }

                /**
                 * LXC container index (per node).
                 */
                public JSONObject vmlist() throws JSONException {
                    return _client.get("/nodes/" + _node + "/lxc", null);
                }

                /**
                 * Create or restore a container.
                 *
                 * @param ostemplate The OS template or backup file.
                 * @param vmid The (unique) ID of the VM.
                 * @param arch OS architecture type. Enum: amd64,i386
                 * @param cmode Console mode. By default, the console command
                 * tries to open a connection to one of the available tty
                 * devices. By setting cmode to 'console' it tries to attach to
                 * /dev/console instead. If you set cmode to 'shell', it simply
                 * invokes a shell inside the container (no login). Enum:
                 * shell,console,tty
                 * @param console Attach a console device (/dev/console) to the
                 * container.
                 * @param cores The number of cores assigned to the container. A
                 * container can use all available cores by default.
                 * @param cpulimit Limit of CPU usage. NOTE: If the computer has
                 * 2 CPUs, it has a total of '2' CPU time. Value '0' indicates
                 * no CPU limit.
                 * @param cpuunits CPU weight for a VM. Argument is used in the
                 * kernel fair scheduler. The larger the number is, the more CPU
                 * time this VM gets. Number is relative to the weights of all
                 * the other running VMs. NOTE: You can disable fair-scheduler
                 * configuration by setting this to 0.
                 * @param description Container description. Only used on the
                 * configuration web interface.
                 * @param force Allow to overwrite existing container.
                 * @param hostname Set a host name for the container.
                 * @param ignore_unpack_errors Ignore errors when extracting the
                 * template.
                 * @param lock_ Lock/unlock the VM. Enum:
                 * migrate,backup,snapshot,rollback
                 * @param memory Amount of RAM for the VM in MB.
                 * @param mpN Use volume as container mount point.
                 * @param nameserver Sets DNS server IP address for a container.
                 * Create will automatically use the setting from the host if
                 * you neither set searchdomain nor nameserver.
                 * @param netN Specifies network interfaces for the container.
                 * @param onboot Specifies whether a VM will be started during
                 * system bootup.
                 * @param ostype OS type. This is used to setup configuration
                 * inside the container, and corresponds to lxc setup scripts in
                 * /usr/share/lxc/config/&amp;lt;ostype&amp;gt;.common.conf.
                 * Value 'unmanaged' can be used to skip and OS specific setup.
                 * Enum:
                 * debian,ubuntu,centos,fedora,opensuse,archlinux,alpine,gentoo,unmanaged
                 * @param password Sets root password inside container.
                 * @param pool Add the VM to the specified pool.
                 * @param protection Sets the protection flag of the container.
                 * This will prevent the CT or CT's disk remove/update
                 * operation.
                 * @param restore Mark this as restore task.
                 * @param rootfs Use volume as container root.
                 * @param searchdomain Sets DNS search domains for a container.
                 * Create will automatically use the setting from the host if
                 * you neither set searchdomain nor nameserver.
                 * @param ssh_public_keys Setup public SSH keys (one key per
                 * line, OpenSSH format).
                 * @param startup Startup and shutdown behavior. Order is a
                 * non-negative number defining the general startup order.
                 * Shutdown in done with reverse ordering. Additionally you can
                 * set the 'up' or 'down' delay in seconds, which specifies a
                 * delay to wait before the next VM is started or stopped.
                 * @param storage Default Storage.
                 * @param swap Amount of SWAP for the VM in MB.
                 * @param template Enable/disable Template.
                 * @param tty Specify the number of tty available to the
                 * container
                 * @param unprivileged Makes the container run as unprivileged
                 * user. (Should not be modified manually.)
                 * @param unusedN Reference to unused volumes. This is used
                 * internally, and should not be modified manually.
                 */
                public JSONObject createVm(String ostemplate, int vmid, String arch, String cmode, Boolean console, Integer cores, Integer cpulimit, Integer cpuunits, String description, Boolean force, String hostname, Boolean ignore_unpack_errors, String lock_, Integer memory, Map<Integer, String> mpN, String nameserver, Map<Integer, String> netN, Boolean onboot, String ostype, String password, String pool, Boolean protection, Boolean restore, String rootfs, String searchdomain, String ssh_public_keys, String startup, String storage, Integer swap, Boolean template, Integer tty, Boolean unprivileged, Map<Integer, String> unusedN) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("ostemplate", ostemplate);
                    parameters.put("vmid", vmid);
                    parameters.put("arch", arch);
                    parameters.put("cmode", cmode);
                    parameters.put("console", console);
                    parameters.put("cores", cores);
                    parameters.put("cpulimit", cpulimit);
                    parameters.put("cpuunits", cpuunits);
                    parameters.put("description", description);
                    parameters.put("force", force);
                    parameters.put("hostname", hostname);
                    parameters.put("ignore-unpack-errors", ignore_unpack_errors);
                    parameters.put("lock", lock_);
                    parameters.put("memory", memory);
                    parameters.put("nameserver", nameserver);
                    parameters.put("onboot", onboot);
                    parameters.put("ostype", ostype);
                    parameters.put("password", password);
                    parameters.put("pool", pool);
                    parameters.put("protection", protection);
                    parameters.put("restore", restore);
                    parameters.put("rootfs", rootfs);
                    parameters.put("searchdomain", searchdomain);
                    parameters.put("ssh-public-keys", ssh_public_keys);
                    parameters.put("startup", startup);
                    parameters.put("storage", storage);
                    parameters.put("swap", swap);
                    parameters.put("template", template);
                    parameters.put("tty", tty);
                    parameters.put("unprivileged", unprivileged);
                    addIndexedParmeter(parameters, "mp", mpN);
                    addIndexedParmeter(parameters, "net", netN);
                    addIndexedParmeter(parameters, "unused", unusedN);
                    return _client.post("/nodes/" + _node + "/lxc", parameters);
                }

                /**
                 * Create or restore a container.
                 *
                 * @param ostemplate The OS template or backup file.
                 * @param vmid The (unique) ID of the VM.
                 */
                public JSONObject createVm(String ostemplate, int vmid) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("ostemplate", ostemplate);
                    parameters.put("vmid", vmid);
                    return _client.post("/nodes/" + _node + "/lxc", parameters);
                }
            }

            public class PVECeph extends Base {

                private Object _node;

                protected PVECeph(Client client, Object node) {
                    _client = client;
                    _node = node;
                }
                private PVEOsd _osd;

                public PVEOsd getOsd() {
                    if (_osd == null) {
                        _osd = new PVEOsd(_client, _node);
                    }
                    return _osd;
                }
                private PVEDisks _disks;

                public PVEDisks getDisks() {
                    if (_disks == null) {
                        _disks = new PVEDisks(_client, _node);
                    }
                    return _disks;
                }
                private PVEConfig _config;

                public PVEConfig getConfig() {
                    if (_config == null) {
                        _config = new PVEConfig(_client, _node);
                    }
                    return _config;
                }
                private PVEMon _mon;

                public PVEMon getMon() {
                    if (_mon == null) {
                        _mon = new PVEMon(_client, _node);
                    }
                    return _mon;
                }
                private PVEInit _init;

                public PVEInit getInit() {
                    if (_init == null) {
                        _init = new PVEInit(_client, _node);
                    }
                    return _init;
                }
                private PVEStop _stop;

                public PVEStop getStop() {
                    if (_stop == null) {
                        _stop = new PVEStop(_client, _node);
                    }
                    return _stop;
                }
                private PVEStart _start;

                public PVEStart getStart() {
                    if (_start == null) {
                        _start = new PVEStart(_client, _node);
                    }
                    return _start;
                }
                private PVEStatus _status;

                public PVEStatus getStatus() {
                    if (_status == null) {
                        _status = new PVEStatus(_client, _node);
                    }
                    return _status;
                }
                private PVEPools _pools;

                public PVEPools getPools() {
                    if (_pools == null) {
                        _pools = new PVEPools(_client, _node);
                    }
                    return _pools;
                }
                private PVEFlags _flags;

                public PVEFlags getFlags() {
                    if (_flags == null) {
                        _flags = new PVEFlags(_client, _node);
                    }
                    return _flags;
                }
                private PVECrush _crush;

                public PVECrush getCrush() {
                    if (_crush == null) {
                        _crush = new PVECrush(_client, _node);
                    }
                    return _crush;
                }
                private PVELog _log;

                public PVELog getLog() {
                    if (_log == null) {
                        _log = new PVELog(_client, _node);
                    }
                    return _log;
                }

                public class PVEOsd extends Base {

                    private Object _node;

                    protected PVEOsd(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    public PVEItemOsdid get(Object osdid) {
                        return new PVEItemOsdid(_client, _node, osdid);
                    }

                    public class PVEItemOsdid extends Base {

                        private Object _node;
                        private Object _osdid;

                        protected PVEItemOsdid(Client client, Object node, Object osdid) {
                            _client = client;
                            _node = node;
                            _osdid = osdid;
                        }
                        private PVEIn _in;

                        public PVEIn getIn() {
                            if (_in == null) {
                                _in = new PVEIn(_client, _node, _osdid);
                            }
                            return _in;
                        }
                        private PVEOut _out;

                        public PVEOut getOut() {
                            if (_out == null) {
                                _out = new PVEOut(_client, _node, _osdid);
                            }
                            return _out;
                        }

                        public class PVEIn extends Base {

                            private Object _node;
                            private Object _osdid;

                            protected PVEIn(Client client, Object node, Object osdid) {
                                _client = client;
                                _node = node;
                                _osdid = osdid;
                            }

                            /**
                             * ceph osd in
                             */
                            public void in() throws JSONException {
                                _client.post("/nodes/" + _node + "/ceph/osd/" + _osdid + "/in", null);
                            }
                        }

                        public class PVEOut extends Base {

                            private Object _node;
                            private Object _osdid;

                            protected PVEOut(Client client, Object node, Object osdid) {
                                _client = client;
                                _node = node;
                                _osdid = osdid;
                            }

                            /**
                             * ceph osd out
                             */
                            public void out() throws JSONException {
                                _client.post("/nodes/" + _node + "/ceph/osd/" + _osdid + "/out", null);
                            }
                        }

                        /**
                         * Destroy OSD
                         *
                         * @param cleanup If set, we remove partition table
                         * entries.
                         */
                        public JSONObject destroyosd(Boolean cleanup) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("cleanup", cleanup);
                            return _client.delete("/nodes/" + _node + "/ceph/osd/" + _osdid + "", parameters);
                        }

                        /**
                         * Destroy OSD
                         */
                        public JSONObject destroyosd() throws JSONException {
                            return _client.delete("/nodes/" + _node + "/ceph/osd/" + _osdid + "", null);
                        }
                    }

                    /**
                     * Get Ceph osd list/tree.
                     */
                    public JSONObject index() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/osd", null);
                    }

                    /**
                     * Create OSD
                     *
                     * @param dev Block device name.
                     * @param bluestore Use bluestore instead of filestore.
                     * @param fstype File system type (filestore only). Enum:
                     * xfs,ext4,btrfs
                     * @param journal_dev Block device name for journal.
                     */
                    public JSONObject createosd(String dev, Boolean bluestore, String fstype, String journal_dev) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("dev", dev);
                        parameters.put("bluestore", bluestore);
                        parameters.put("fstype", fstype);
                        parameters.put("journal_dev", journal_dev);
                        return _client.post("/nodes/" + _node + "/ceph/osd", parameters);
                    }

                    /**
                     * Create OSD
                     *
                     * @param dev Block device name.
                     */
                    public JSONObject createosd(String dev) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("dev", dev);
                        return _client.post("/nodes/" + _node + "/ceph/osd", parameters);
                    }
                }

                public class PVEDisks extends Base {

                    private Object _node;

                    protected PVEDisks(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * List local disks.
                     *
                     * @param type Only list specific types of disks. Enum:
                     * unused,journal_disks
                     */
                    public JSONObject disks(String type) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("type", type);
                        return _client.get("/nodes/" + _node + "/ceph/disks", parameters);
                    }

                    /**
                     * List local disks.
                     */
                    public JSONObject disks() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/disks", null);
                    }
                }

                public class PVEConfig extends Base {

                    private Object _node;

                    protected PVEConfig(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Get Ceph configuration.
                     */
                    public JSONObject config() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/config", null);
                    }
                }

                public class PVEMon extends Base {

                    private Object _node;

                    protected PVEMon(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    public PVEItemMonid get(Object monid) {
                        return new PVEItemMonid(_client, _node, monid);
                    }

                    public class PVEItemMonid extends Base {

                        private Object _node;
                        private Object _monid;

                        protected PVEItemMonid(Client client, Object node, Object monid) {
                            _client = client;
                            _node = node;
                            _monid = monid;
                        }

                        /**
                         * Destroy Ceph monitor.
                         */
                        public JSONObject destroymon() throws JSONException {
                            return _client.delete("/nodes/" + _node + "/ceph/mon/" + _monid + "", null);
                        }
                    }

                    /**
                     * Get Ceph monitor list.
                     */
                    public JSONObject listmon() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/mon", null);
                    }

                    /**
                     * Create Ceph Monitor
                     */
                    public JSONObject createmon() throws JSONException {
                        return _client.post("/nodes/" + _node + "/ceph/mon", null);
                    }
                }

                public class PVEInit extends Base {

                    private Object _node;

                    protected PVEInit(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Create initial ceph default configuration and setup
                     * symlinks.
                     *
                     * @param disable_cephx Disable cephx authentification.
                     * WARNING: cephx is a security feature protecting against
                     * man-in-the-middle attacks. Only consider disabling cephx
                     * if your network is private!
                     * @param min_size Minimum number of available replicas per
                     * object to allow I/O
                     * @param network Use specific network for all ceph related
                     * traffic
                     * @param pg_bits Placement group bits, used to specify the
                     * default number of placement groups. NOTE: 'osd pool
                     * default pg num' does not work for default pools.
                     * @param size Targeted number of replicas per object
                     */
                    public void init(Boolean disable_cephx, Integer min_size, String network, Integer pg_bits, Integer size) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("disable_cephx", disable_cephx);
                        parameters.put("min_size", min_size);
                        parameters.put("network", network);
                        parameters.put("pg_bits", pg_bits);
                        parameters.put("size", size);
                        _client.post("/nodes/" + _node + "/ceph/init", parameters);
                    }

                    /**
                     * Create initial ceph default configuration and setup
                     * symlinks.
                     */
                    public void init() throws JSONException {
                        _client.post("/nodes/" + _node + "/ceph/init", null);
                    }
                }

                public class PVEStop extends Base {

                    private Object _node;

                    protected PVEStop(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Stop ceph services.
                     *
                     * @param service Ceph service name.
                     */
                    public JSONObject stop(String service) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("service", service);
                        return _client.post("/nodes/" + _node + "/ceph/stop", parameters);
                    }

                    /**
                     * Stop ceph services.
                     */
                    public JSONObject stop() throws JSONException {
                        return _client.post("/nodes/" + _node + "/ceph/stop", null);
                    }
                }

                public class PVEStart extends Base {

                    private Object _node;

                    protected PVEStart(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Start ceph services.
                     *
                     * @param service Ceph service name.
                     */
                    public JSONObject start(String service) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("service", service);
                        return _client.post("/nodes/" + _node + "/ceph/start", parameters);
                    }

                    /**
                     * Start ceph services.
                     */
                    public JSONObject start() throws JSONException {
                        return _client.post("/nodes/" + _node + "/ceph/start", null);
                    }
                }

                public class PVEStatus extends Base {

                    private Object _node;

                    protected PVEStatus(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Get ceph status.
                     */
                    public JSONObject status() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/status", null);
                    }
                }

                public class PVEPools extends Base {

                    private Object _node;

                    protected PVEPools(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    public PVEItemName get(Object name) {
                        return new PVEItemName(_client, _node, name);
                    }

                    public class PVEItemName extends Base {

                        private Object _node;
                        private Object _name;

                        protected PVEItemName(Client client, Object node, Object name) {
                            _client = client;
                            _node = node;
                            _name = name;
                        }

                        /**
                         * Destroy pool
                         *
                         * @param force If true, destroys pool even if in use
                         */
                        public void destroypool(Boolean force) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("force", force);
                            _client.delete("/nodes/" + _node + "/ceph/pools/" + _name + "", parameters);
                        }

                        /**
                         * Destroy pool
                         */
                        public void destroypool() throws JSONException {
                            _client.delete("/nodes/" + _node + "/ceph/pools/" + _name + "", null);
                        }
                    }

                    /**
                     * List all pools.
                     */
                    public JSONObject lspools() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/pools", null);
                    }

                    /**
                     * Create POOL
                     *
                     * @param name The name of the pool. It must be unique.
                     * @param crush_ruleset The ruleset to use for mapping
                     * object placement in the cluster.
                     * @param min_size Minimum number of replicas per object
                     * @param pg_num Number of placement groups.
                     * @param size Number of replicas per object
                     */
                    public void createpool(String name, Integer crush_ruleset, Integer min_size, Integer pg_num, Integer size) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("name", name);
                        parameters.put("crush_ruleset", crush_ruleset);
                        parameters.put("min_size", min_size);
                        parameters.put("pg_num", pg_num);
                        parameters.put("size", size);
                        _client.post("/nodes/" + _node + "/ceph/pools", parameters);
                    }

                    /**
                     * Create POOL
                     *
                     * @param name The name of the pool. It must be unique.
                     */
                    public void createpool(String name) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("name", name);
                        _client.post("/nodes/" + _node + "/ceph/pools", parameters);
                    }
                }

                public class PVEFlags extends Base {

                    private Object _node;

                    protected PVEFlags(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    public PVEItemFlag get(Object flag) {
                        return new PVEItemFlag(_client, _node, flag);
                    }

                    public class PVEItemFlag extends Base {

                        private Object _node;
                        private Object _flag;

                        protected PVEItemFlag(Client client, Object node, Object flag) {
                            _client = client;
                            _node = node;
                            _flag = flag;
                        }

                        /**
                         * Unset a ceph flag
                         */
                        public void unsetFlag() throws JSONException {
                            _client.delete("/nodes/" + _node + "/ceph/flags/" + _flag + "", null);
                        }

                        /**
                         * Set a ceph flag
                         */
                        public void setFlag() throws JSONException {
                            _client.post("/nodes/" + _node + "/ceph/flags/" + _flag + "", null);
                        }
                    }

                    /**
                     * get all set ceph flags
                     */
                    public JSONObject getFlags() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/flags", null);
                    }
                }

                public class PVECrush extends Base {

                    private Object _node;

                    protected PVECrush(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Get OSD crush map
                     */
                    public JSONObject crush() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/crush", null);
                    }
                }

                public class PVELog extends Base {

                    private Object _node;

                    protected PVELog(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Read ceph log
                     *
                     * @param limit
                     * @param start
                     */
                    public JSONObject log(Integer limit, Integer start) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("limit", limit);
                        parameters.put("start", start);
                        return _client.get("/nodes/" + _node + "/ceph/log", parameters);
                    }

                    /**
                     * Read ceph log
                     */
                    public JSONObject log() throws JSONException {
                        return _client.get("/nodes/" + _node + "/ceph/log", null);
                    }
                }

                /**
                 * Directory index.
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/nodes/" + _node + "/ceph", null);
                }
            }

            public class PVEVzdump extends Base {

                private Object _node;

                protected PVEVzdump(Client client, Object node) {
                    _client = client;
                    _node = node;
                }
                private PVEExtractconfig _extractconfig;

                public PVEExtractconfig getExtractconfig() {
                    if (_extractconfig == null) {
                        _extractconfig = new PVEExtractconfig(_client, _node);
                    }
                    return _extractconfig;
                }

                public class PVEExtractconfig extends Base {

                    private Object _node;

                    protected PVEExtractconfig(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Extract configuration from vzdump backup archive.
                     *
                     * @param volume Volume identifier
                     */
                    public JSONObject extractconfig(String volume) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("volume", volume);
                        return _client.get("/nodes/" + _node + "/vzdump/extractconfig", parameters);
                    }
                }

                /**
                 * Create backup.
                 *
                 * @param all Backup all known guest systems on this host.
                 * @param bwlimit Limit I/O bandwidth (KBytes per second).
                 * @param compress Compress dump file. Enum: 0,1,gzip,lzo
                 * @param dumpdir Store resulting files to specified directory.
                 * @param exclude Exclude specified guest systems (assumes
                 * --all)
                 * @param exclude_path Exclude certain files/directories (shell
                 * globs).
                 * @param ionice Set CFQ ionice priority.
                 * @param lockwait Maximal time to wait for the global lock
                 * (minutes).
                 * @param mailnotification Specify when to send an email Enum:
                 * always,failure
                 * @param mailto Comma-separated list of email addresses that
                 * should receive email notifications.
                 * @param maxfiles Maximal number of backup files per guest
                 * system.
                 * @param mode Backup mode. Enum: snapshot,suspend,stop
                 * @param pigz Use pigz instead of gzip when N&amp;gt;0. N=1
                 * uses half of cores, N&amp;gt;1 uses N as thread count.
                 * @param quiet Be quiet.
                 * @param remove Remove old backup files if there are more than
                 * 'maxfiles' backup files.
                 * @param script Use specified hook script.
                 * @param size Unused, will be removed in a future release.
                 * @param stdexcludes Exclude temporary files and logs.
                 * @param stdout Write tar to stdout, not to a file.
                 * @param stop Stop runnig backup jobs on this host.
                 * @param stopwait Maximal time to wait until a guest system is
                 * stopped (minutes).
                 * @param storage Store resulting file to this storage.
                 * @param tmpdir Store temporary files to specified directory.
                 * @param vmid The ID of the guest system you want to backup.
                 */
                public JSONObject vzdump(Boolean all, Integer bwlimit, String compress, String dumpdir, String exclude, String exclude_path, Integer ionice, Integer lockwait, String mailnotification, String mailto, Integer maxfiles, String mode, Integer pigz, Boolean quiet, Boolean remove, String script, Integer size, Boolean stdexcludes, Boolean stdout, Boolean stop, Integer stopwait, String storage, String tmpdir, String vmid) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("all", all);
                    parameters.put("bwlimit", bwlimit);
                    parameters.put("compress", compress);
                    parameters.put("dumpdir", dumpdir);
                    parameters.put("exclude", exclude);
                    parameters.put("exclude-path", exclude_path);
                    parameters.put("ionice", ionice);
                    parameters.put("lockwait", lockwait);
                    parameters.put("mailnotification", mailnotification);
                    parameters.put("mailto", mailto);
                    parameters.put("maxfiles", maxfiles);
                    parameters.put("mode", mode);
                    parameters.put("pigz", pigz);
                    parameters.put("quiet", quiet);
                    parameters.put("remove", remove);
                    parameters.put("script", script);
                    parameters.put("size", size);
                    parameters.put("stdexcludes", stdexcludes);
                    parameters.put("stdout", stdout);
                    parameters.put("stop", stop);
                    parameters.put("stopwait", stopwait);
                    parameters.put("storage", storage);
                    parameters.put("tmpdir", tmpdir);
                    parameters.put("vmid", vmid);
                    return _client.post("/nodes/" + _node + "/vzdump", parameters);
                }

                /**
                 * Create backup.
                 */
                public JSONObject vzdump() throws JSONException {
                    return _client.post("/nodes/" + _node + "/vzdump", null);
                }
            }

            public class PVEServices extends Base {

                private Object _node;

                protected PVEServices(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                public PVEItemService get(Object service) {
                    return new PVEItemService(_client, _node, service);
                }

                public class PVEItemService extends Base {

                    private Object _node;
                    private Object _service;

                    protected PVEItemService(Client client, Object node, Object service) {
                        _client = client;
                        _node = node;
                        _service = service;
                    }
                    private PVEState _state;

                    public PVEState getState() {
                        if (_state == null) {
                            _state = new PVEState(_client, _node, _service);
                        }
                        return _state;
                    }
                    private PVEStart _start;

                    public PVEStart getStart() {
                        if (_start == null) {
                            _start = new PVEStart(_client, _node, _service);
                        }
                        return _start;
                    }
                    private PVEStop _stop;

                    public PVEStop getStop() {
                        if (_stop == null) {
                            _stop = new PVEStop(_client, _node, _service);
                        }
                        return _stop;
                    }
                    private PVERestart _restart;

                    public PVERestart getRestart() {
                        if (_restart == null) {
                            _restart = new PVERestart(_client, _node, _service);
                        }
                        return _restart;
                    }
                    private PVEReload _reload;

                    public PVEReload getReload() {
                        if (_reload == null) {
                            _reload = new PVEReload(_client, _node, _service);
                        }
                        return _reload;
                    }

                    public class PVEState extends Base {

                        private Object _node;
                        private Object _service;

                        protected PVEState(Client client, Object node, Object service) {
                            _client = client;
                            _node = node;
                            _service = service;
                        }

                        /**
                         * Read service properties
                         */
                        public JSONObject serviceState() throws JSONException {
                            return _client.get("/nodes/" + _node + "/services/" + _service + "/state", null);
                        }
                    }

                    public class PVEStart extends Base {

                        private Object _node;
                        private Object _service;

                        protected PVEStart(Client client, Object node, Object service) {
                            _client = client;
                            _node = node;
                            _service = service;
                        }

                        /**
                         * Start service.
                         */
                        public JSONObject serviceStart() throws JSONException {
                            return _client.post("/nodes/" + _node + "/services/" + _service + "/start", null);
                        }
                    }

                    public class PVEStop extends Base {

                        private Object _node;
                        private Object _service;

                        protected PVEStop(Client client, Object node, Object service) {
                            _client = client;
                            _node = node;
                            _service = service;
                        }

                        /**
                         * Stop service.
                         */
                        public JSONObject serviceStop() throws JSONException {
                            return _client.post("/nodes/" + _node + "/services/" + _service + "/stop", null);
                        }
                    }

                    public class PVERestart extends Base {

                        private Object _node;
                        private Object _service;

                        protected PVERestart(Client client, Object node, Object service) {
                            _client = client;
                            _node = node;
                            _service = service;
                        }

                        /**
                         * Restart service.
                         */
                        public JSONObject serviceRestart() throws JSONException {
                            return _client.post("/nodes/" + _node + "/services/" + _service + "/restart", null);
                        }
                    }

                    public class PVEReload extends Base {

                        private Object _node;
                        private Object _service;

                        protected PVEReload(Client client, Object node, Object service) {
                            _client = client;
                            _node = node;
                            _service = service;
                        }

                        /**
                         * Reload service.
                         */
                        public JSONObject serviceReload() throws JSONException {
                            return _client.post("/nodes/" + _node + "/services/" + _service + "/reload", null);
                        }
                    }

                    /**
                     * Directory index
                     */
                    public JSONObject srvcmdidx() throws JSONException {
                        return _client.get("/nodes/" + _node + "/services/" + _service + "", null);
                    }
                }

                /**
                 * Service list.
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/nodes/" + _node + "/services", null);
                }
            }

            public class PVESubscription extends Base {

                private Object _node;

                protected PVESubscription(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Read subscription info.
                 */
                public JSONObject get() throws JSONException {
                    return _client.get("/nodes/" + _node + "/subscription", null);
                }

                /**
                 * Update subscription info.
                 *
                 * @param force Always connect to server, even if we have up to
                 * date info inside local cache.
                 */
                public void update(Boolean force) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("force", force);
                    _client.post("/nodes/" + _node + "/subscription", parameters);
                }

                /**
                 * Update subscription info.
                 */
                public void update() throws JSONException {
                    _client.post("/nodes/" + _node + "/subscription", null);
                }

                /**
                 * Set subscription key.
                 *
                 * @param key Proxmox VE subscription key
                 */
                public void set(String key) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("key", key);
                    _client.put("/nodes/" + _node + "/subscription", parameters);
                }
            }

            public class PVENetwork extends Base {

                private Object _node;

                protected PVENetwork(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                public PVEItemIface get(Object iface) {
                    return new PVEItemIface(_client, _node, iface);
                }

                public class PVEItemIface extends Base {

                    private Object _node;
                    private Object _iface;

                    protected PVEItemIface(Client client, Object node, Object iface) {
                        _client = client;
                        _node = node;
                        _iface = iface;
                    }

                    /**
                     * Delete network device configuration
                     */
                    public void deleteNetwork() throws JSONException {
                        _client.delete("/nodes/" + _node + "/network/" + _iface + "", null);
                    }

                    /**
                     * Read network device configuration
                     */
                    public JSONObject networkConfig() throws JSONException {
                        return _client.get("/nodes/" + _node + "/network/" + _iface + "", null);
                    }

                    /**
                     * Update network device configuration
                     *
                     * @param type Network interface type Enum:
                     * bridge,bond,eth,alias,vlan,OVSBridge,OVSBond,OVSPort,OVSIntPort,unknown
                     * @param address IP address.
                     * @param address6 IP address.
                     * @param autostart Automatically start interface on boot.
                     * @param bond_mode Bonding mode. Enum:
                     * balance-rr,active-backup,balance-xor,broadcast,802.3ad,balance-tlb,balance-alb,balance-slb,lacp-balance-slb,lacp-balance-tcp
                     * @param bond_xmit_hash_policy Selects the transmit hash
                     * policy to use for slave selection in balance-xor and
                     * 802.3ad modes. Enum: layer2,layer2+3,layer3+4
                     * @param bridge_ports Specify the iterfaces you want to add
                     * to your bridge.
                     * @param bridge_vlan_aware Enable bridge vlan support.
                     * @param comments Comments
                     * @param comments6 Comments
                     * @param delete A list of settings you want to delete.
                     * @param gateway Default gateway address.
                     * @param gateway6 Default ipv6 gateway address.
                     * @param netmask Network mask.
                     * @param netmask6 Network mask.
                     * @param ovs_bonds Specify the interfaces used by the
                     * bonding device.
                     * @param ovs_bridge The OVS bridge associated with a OVS
                     * port. This is required when you create an OVS port.
                     * @param ovs_options OVS interface options.
                     * @param ovs_ports Specify the iterfaces you want to add to
                     * your bridge.
                     * @param ovs_tag Specify a VLan tag (used by OVSPort,
                     * OVSIntPort, OVSBond)
                     * @param slaves Specify the interfaces used by the bonding
                     * device.
                     */
                    public void updateNetwork(String type, String address, String address6, Boolean autostart, String bond_mode, String bond_xmit_hash_policy, String bridge_ports, Boolean bridge_vlan_aware, String comments, String comments6, String delete, String gateway, String gateway6, String netmask, Integer netmask6, String ovs_bonds, String ovs_bridge, String ovs_options, String ovs_ports, Integer ovs_tag, String slaves) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("type", type);
                        parameters.put("address", address);
                        parameters.put("address6", address6);
                        parameters.put("autostart", autostart);
                        parameters.put("bond_mode", bond_mode);
                        parameters.put("bond_xmit_hash_policy", bond_xmit_hash_policy);
                        parameters.put("bridge_ports", bridge_ports);
                        parameters.put("bridge_vlan_aware", bridge_vlan_aware);
                        parameters.put("comments", comments);
                        parameters.put("comments6", comments6);
                        parameters.put("delete", delete);
                        parameters.put("gateway", gateway);
                        parameters.put("gateway6", gateway6);
                        parameters.put("netmask", netmask);
                        parameters.put("netmask6", netmask6);
                        parameters.put("ovs_bonds", ovs_bonds);
                        parameters.put("ovs_bridge", ovs_bridge);
                        parameters.put("ovs_options", ovs_options);
                        parameters.put("ovs_ports", ovs_ports);
                        parameters.put("ovs_tag", ovs_tag);
                        parameters.put("slaves", slaves);
                        _client.put("/nodes/" + _node + "/network/" + _iface + "", parameters);
                    }

                    /**
                     * Update network device configuration
                     *
                     * @param type Network interface type Enum:
                     * bridge,bond,eth,alias,vlan,OVSBridge,OVSBond,OVSPort,OVSIntPort,unknown
                     */
                    public void updateNetwork(String type) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("type", type);
                        _client.put("/nodes/" + _node + "/network/" + _iface + "", parameters);
                    }
                }

                /**
                 * Revert network configuration changes.
                 */
                public void revertNetworkChanges() throws JSONException {
                    _client.delete("/nodes/" + _node + "/network", null);
                }

                /**
                 * List available networks
                 *
                 * @param type Only list specific interface types. Enum:
                 * bridge,bond,eth,alias,vlan,OVSBridge,OVSBond,OVSPort,OVSIntPort,any_bridge
                 */
                public JSONObject index(String type) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("type", type);
                    return _client.get("/nodes/" + _node + "/network", parameters);
                }

                /**
                 * List available networks
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/nodes/" + _node + "/network", null);
                }

                /**
                 * Create network device configuration
                 *
                 * @param iface Network interface name.
                 * @param type Network interface type Enum:
                 * bridge,bond,eth,alias,vlan,OVSBridge,OVSBond,OVSPort,OVSIntPort,unknown
                 * @param address IP address.
                 * @param address6 IP address.
                 * @param autostart Automatically start interface on boot.
                 * @param bond_mode Bonding mode. Enum:
                 * balance-rr,active-backup,balance-xor,broadcast,802.3ad,balance-tlb,balance-alb,balance-slb,lacp-balance-slb,lacp-balance-tcp
                 * @param bond_xmit_hash_policy Selects the transmit hash policy
                 * to use for slave selection in balance-xor and 802.3ad modes.
                 * Enum: layer2,layer2+3,layer3+4
                 * @param bridge_ports Specify the iterfaces you want to add to
                 * your bridge.
                 * @param bridge_vlan_aware Enable bridge vlan support.
                 * @param comments Comments
                 * @param comments6 Comments
                 * @param gateway Default gateway address.
                 * @param gateway6 Default ipv6 gateway address.
                 * @param netmask Network mask.
                 * @param netmask6 Network mask.
                 * @param ovs_bonds Specify the interfaces used by the bonding
                 * device.
                 * @param ovs_bridge The OVS bridge associated with a OVS port.
                 * This is required when you create an OVS port.
                 * @param ovs_options OVS interface options.
                 * @param ovs_ports Specify the iterfaces you want to add to
                 * your bridge.
                 * @param ovs_tag Specify a VLan tag (used by OVSPort,
                 * OVSIntPort, OVSBond)
                 * @param slaves Specify the interfaces used by the bonding
                 * device.
                 */
                public void createNetwork(String iface, String type, String address, String address6, Boolean autostart, String bond_mode, String bond_xmit_hash_policy, String bridge_ports, Boolean bridge_vlan_aware, String comments, String comments6, String gateway, String gateway6, String netmask, Integer netmask6, String ovs_bonds, String ovs_bridge, String ovs_options, String ovs_ports, Integer ovs_tag, String slaves) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("iface", iface);
                    parameters.put("type", type);
                    parameters.put("address", address);
                    parameters.put("address6", address6);
                    parameters.put("autostart", autostart);
                    parameters.put("bond_mode", bond_mode);
                    parameters.put("bond_xmit_hash_policy", bond_xmit_hash_policy);
                    parameters.put("bridge_ports", bridge_ports);
                    parameters.put("bridge_vlan_aware", bridge_vlan_aware);
                    parameters.put("comments", comments);
                    parameters.put("comments6", comments6);
                    parameters.put("gateway", gateway);
                    parameters.put("gateway6", gateway6);
                    parameters.put("netmask", netmask);
                    parameters.put("netmask6", netmask6);
                    parameters.put("ovs_bonds", ovs_bonds);
                    parameters.put("ovs_bridge", ovs_bridge);
                    parameters.put("ovs_options", ovs_options);
                    parameters.put("ovs_ports", ovs_ports);
                    parameters.put("ovs_tag", ovs_tag);
                    parameters.put("slaves", slaves);
                    _client.post("/nodes/" + _node + "/network", parameters);
                }

                /**
                 * Create network device configuration
                 *
                 * @param iface Network interface name.
                 * @param type Network interface type Enum:
                 * bridge,bond,eth,alias,vlan,OVSBridge,OVSBond,OVSPort,OVSIntPort,unknown
                 */
                public void createNetwork(String iface, String type) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("iface", iface);
                    parameters.put("type", type);
                    _client.post("/nodes/" + _node + "/network", parameters);
                }
            }

            public class PVETasks extends Base {

                private Object _node;

                protected PVETasks(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                public PVEItemUpid get(Object upid) {
                    return new PVEItemUpid(_client, _node, upid);
                }

                public class PVEItemUpid extends Base {

                    private Object _node;
                    private Object _upid;

                    protected PVEItemUpid(Client client, Object node, Object upid) {
                        _client = client;
                        _node = node;
                        _upid = upid;
                    }
                    private PVELog _log;

                    public PVELog getLog() {
                        if (_log == null) {
                            _log = new PVELog(_client, _node, _upid);
                        }
                        return _log;
                    }
                    private PVEStatus _status;

                    public PVEStatus getStatus() {
                        if (_status == null) {
                            _status = new PVEStatus(_client, _node, _upid);
                        }
                        return _status;
                    }

                    public class PVELog extends Base {

                        private Object _node;
                        private Object _upid;

                        protected PVELog(Client client, Object node, Object upid) {
                            _client = client;
                            _node = node;
                            _upid = upid;
                        }

                        /**
                         * Read task log.
                         *
                         * @param limit
                         * @param start
                         */
                        public JSONObject readTaskLog(Integer limit, Integer start) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("limit", limit);
                            parameters.put("start", start);
                            return _client.get("/nodes/" + _node + "/tasks/" + _upid + "/log", parameters);
                        }

                        /**
                         * Read task log.
                         */
                        public JSONObject readTaskLog() throws JSONException {
                            return _client.get("/nodes/" + _node + "/tasks/" + _upid + "/log", null);
                        }
                    }

                    public class PVEStatus extends Base {

                        private Object _node;
                        private Object _upid;

                        protected PVEStatus(Client client, Object node, Object upid) {
                            _client = client;
                            _node = node;
                            _upid = upid;
                        }

                        /**
                         * Read task status.
                         */
                        public JSONObject readTaskStatus() throws JSONException {
                            return _client.get("/nodes/" + _node + "/tasks/" + _upid + "/status", null);
                        }
                    }

                    /**
                     * Stop a task.
                     */
                    public void stopTask() throws JSONException {
                        _client.delete("/nodes/" + _node + "/tasks/" + _upid + "", null);
                    }

                    /**
                     *
                     */
                    public JSONObject upidIndex() throws JSONException {
                        return _client.get("/nodes/" + _node + "/tasks/" + _upid + "", null);
                    }
                }

                /**
                 * Read task list for one node (finished tasks).
                 *
                 * @param errors
                 * @param limit
                 * @param start
                 * @param userfilter
                 * @param vmid Only list tasks for this VM.
                 */
                public JSONObject nodeTasks(Boolean errors, Integer limit, Integer start, String userfilter, Integer vmid) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("errors", errors);
                    parameters.put("limit", limit);
                    parameters.put("start", start);
                    parameters.put("userfilter", userfilter);
                    parameters.put("vmid", vmid);
                    return _client.get("/nodes/" + _node + "/tasks", parameters);
                }

                /**
                 * Read task list for one node (finished tasks).
                 */
                public JSONObject nodeTasks() throws JSONException {
                    return _client.get("/nodes/" + _node + "/tasks", null);
                }
            }

            public class PVEScan extends Base {

                private Object _node;

                protected PVEScan(Client client, Object node) {
                    _client = client;
                    _node = node;
                }
                private PVEZfs _zfs;

                public PVEZfs getZfs() {
                    if (_zfs == null) {
                        _zfs = new PVEZfs(_client, _node);
                    }
                    return _zfs;
                }
                private PVENfs _nfs;

                public PVENfs getNfs() {
                    if (_nfs == null) {
                        _nfs = new PVENfs(_client, _node);
                    }
                    return _nfs;
                }
                private PVEGlusterfs _glusterfs;

                public PVEGlusterfs getGlusterfs() {
                    if (_glusterfs == null) {
                        _glusterfs = new PVEGlusterfs(_client, _node);
                    }
                    return _glusterfs;
                }
                private PVEIscsi _iscsi;

                public PVEIscsi getIscsi() {
                    if (_iscsi == null) {
                        _iscsi = new PVEIscsi(_client, _node);
                    }
                    return _iscsi;
                }
                private PVELvm _lvm;

                public PVELvm getLvm() {
                    if (_lvm == null) {
                        _lvm = new PVELvm(_client, _node);
                    }
                    return _lvm;
                }
                private PVELvmthin _lvmthin;

                public PVELvmthin getLvmthin() {
                    if (_lvmthin == null) {
                        _lvmthin = new PVELvmthin(_client, _node);
                    }
                    return _lvmthin;
                }
                private PVEUsb _usb;

                public PVEUsb getUsb() {
                    if (_usb == null) {
                        _usb = new PVEUsb(_client, _node);
                    }
                    return _usb;
                }

                public class PVEZfs extends Base {

                    private Object _node;

                    protected PVEZfs(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Scan zfs pool list on local node.
                     */
                    public JSONObject zfsscan() throws JSONException {
                        return _client.get("/nodes/" + _node + "/scan/zfs", null);
                    }
                }

                public class PVENfs extends Base {

                    private Object _node;

                    protected PVENfs(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Scan remote NFS server.
                     *
                     * @param server
                     */
                    public JSONObject nfsscan(String server) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("server", server);
                        return _client.get("/nodes/" + _node + "/scan/nfs", parameters);
                    }
                }

                public class PVEGlusterfs extends Base {

                    private Object _node;

                    protected PVEGlusterfs(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Scan remote GlusterFS server.
                     *
                     * @param server
                     */
                    public JSONObject glusterfsscan(String server) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("server", server);
                        return _client.get("/nodes/" + _node + "/scan/glusterfs", parameters);
                    }
                }

                public class PVEIscsi extends Base {

                    private Object _node;

                    protected PVEIscsi(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Scan remote iSCSI server.
                     *
                     * @param portal
                     */
                    public JSONObject iscsiscan(String portal) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("portal", portal);
                        return _client.get("/nodes/" + _node + "/scan/iscsi", parameters);
                    }
                }

                public class PVELvm extends Base {

                    private Object _node;

                    protected PVELvm(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * List local LVM volume groups.
                     */
                    public JSONObject lvmscan() throws JSONException {
                        return _client.get("/nodes/" + _node + "/scan/lvm", null);
                    }
                }

                public class PVELvmthin extends Base {

                    private Object _node;

                    protected PVELvmthin(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * List local LVM Thin Pools.
                     *
                     * @param vg
                     */
                    public JSONObject lvmthinscan(String vg) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("vg", vg);
                        return _client.get("/nodes/" + _node + "/scan/lvmthin", parameters);
                    }
                }

                public class PVEUsb extends Base {

                    private Object _node;

                    protected PVEUsb(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * List local USB devices.
                     */
                    public JSONObject usbscan() throws JSONException {
                        return _client.get("/nodes/" + _node + "/scan/usb", null);
                    }
                }

                /**
                 * Index of available scan methods
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/nodes/" + _node + "/scan", null);
                }
            }

            public class PVEStorage extends Base {

                private Object _node;

                protected PVEStorage(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                public PVEItemStorage get(Object storage) {
                    return new PVEItemStorage(_client, _node, storage);
                }

                public class PVEItemStorage extends Base {

                    private Object _node;
                    private Object _storage;

                    protected PVEItemStorage(Client client, Object node, Object storage) {
                        _client = client;
                        _node = node;
                        _storage = storage;
                    }
                    private PVEContent _content;

                    public PVEContent getContent() {
                        if (_content == null) {
                            _content = new PVEContent(_client, _node, _storage);
                        }
                        return _content;
                    }
                    private PVEStatus _status;

                    public PVEStatus getStatus() {
                        if (_status == null) {
                            _status = new PVEStatus(_client, _node, _storage);
                        }
                        return _status;
                    }
                    private PVERrd _rrd;

                    public PVERrd getRrd() {
                        if (_rrd == null) {
                            _rrd = new PVERrd(_client, _node, _storage);
                        }
                        return _rrd;
                    }
                    private PVERrddata _rrddata;

                    public PVERrddata getRrddata() {
                        if (_rrddata == null) {
                            _rrddata = new PVERrddata(_client, _node, _storage);
                        }
                        return _rrddata;
                    }
                    private PVEUpload _upload;

                    public PVEUpload getUpload() {
                        if (_upload == null) {
                            _upload = new PVEUpload(_client, _node, _storage);
                        }
                        return _upload;
                    }

                    public class PVEContent extends Base {

                        private Object _node;
                        private Object _storage;

                        protected PVEContent(Client client, Object node, Object storage) {
                            _client = client;
                            _node = node;
                            _storage = storage;
                        }

                        public PVEItemVolume get(Object volume) {
                            return new PVEItemVolume(_client, _node, _storage, volume);
                        }

                        public class PVEItemVolume extends Base {

                            private Object _node;
                            private Object _storage;
                            private Object _volume;

                            protected PVEItemVolume(Client client, Object node, Object storage, Object volume) {
                                _client = client;
                                _node = node;
                                _storage = storage;
                                _volume = volume;
                            }

                            /**
                             * Delete volume
                             */
                            public void delete() throws JSONException {
                                _client.delete("/nodes/" + _node + "/storage/" + _storage + "/content/" + _volume + "", null);
                            }

                            /**
                             * Get volume attributes
                             */
                            public JSONObject info() throws JSONException {
                                return _client.get("/nodes/" + _node + "/storage/" + _storage + "/content/" + _volume + "", null);
                            }

                            /**
                             * Copy a volume. This is experimental code - do not
                             * use.
                             *
                             * @param target Target volume identifier
                             * @param target_node Target node. Default is local
                             * node.
                             */
                            public JSONObject copy(String target, String target_node) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("target", target);
                                parameters.put("target_node", target_node);
                                return _client.post("/nodes/" + _node + "/storage/" + _storage + "/content/" + _volume + "", parameters);
                            }

                            /**
                             * Copy a volume. This is experimental code - do not
                             * use.
                             *
                             * @param target Target volume identifier
                             */
                            public JSONObject copy(String target) throws JSONException {
                                Map<String, Object> parameters = new HashMap<String, Object>();
                                parameters.put("target", target);
                                return _client.post("/nodes/" + _node + "/storage/" + _storage + "/content/" + _volume + "", parameters);
                            }
                        }

                        /**
                         * List storage content.
                         *
                         * @param content Only list content of this type.
                         * @param vmid Only list images for this VM
                         */
                        public JSONObject index(String content, Integer vmid) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("content", content);
                            parameters.put("vmid", vmid);
                            return _client.get("/nodes/" + _node + "/storage/" + _storage + "/content", parameters);
                        }

                        /**
                         * List storage content.
                         */
                        public JSONObject index() throws JSONException {
                            return _client.get("/nodes/" + _node + "/storage/" + _storage + "/content", null);
                        }

                        /**
                         * Allocate disk images.
                         *
                         * @param filename The name of the file to create.
                         * @param size Size in kilobyte (1024 bytes). Optional
                         * suffixes 'M' (megabyte, 1024K) and 'G' (gigabyte,
                         * 1024M)
                         * @param vmid Specify owner VM
                         * @param format Enum: raw,qcow2,subvol
                         */
                        public JSONObject create(String filename, String size, int vmid, String format) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("filename", filename);
                            parameters.put("size", size);
                            parameters.put("vmid", vmid);
                            parameters.put("format", format);
                            return _client.post("/nodes/" + _node + "/storage/" + _storage + "/content", parameters);
                        }

                        /**
                         * Allocate disk images.
                         *
                         * @param filename The name of the file to create.
                         * @param size Size in kilobyte (1024 bytes). Optional
                         * suffixes 'M' (megabyte, 1024K) and 'G' (gigabyte,
                         * 1024M)
                         * @param vmid Specify owner VM
                         */
                        public JSONObject create(String filename, String size, int vmid) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("filename", filename);
                            parameters.put("size", size);
                            parameters.put("vmid", vmid);
                            return _client.post("/nodes/" + _node + "/storage/" + _storage + "/content", parameters);
                        }
                    }

                    public class PVEStatus extends Base {

                        private Object _node;
                        private Object _storage;

                        protected PVEStatus(Client client, Object node, Object storage) {
                            _client = client;
                            _node = node;
                            _storage = storage;
                        }

                        /**
                         * Read storage status.
                         */
                        public JSONObject readStatus() throws JSONException {
                            return _client.get("/nodes/" + _node + "/storage/" + _storage + "/status", null);
                        }
                    }

                    public class PVERrd extends Base {

                        private Object _node;
                        private Object _storage;

                        protected PVERrd(Client client, Object node, Object storage) {
                            _client = client;
                            _node = node;
                            _storage = storage;
                        }

                        /**
                         * Read storage RRD statistics (returns PNG).
                         *
                         * @param ds The list of datasources you want to
                         * display.
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         * @param cf The RRD consolidation function Enum:
                         * AVERAGE,MAX
                         */
                        public JSONObject rrd(String ds, String timeframe, String cf) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("ds", ds);
                            parameters.put("timeframe", timeframe);
                            parameters.put("cf", cf);
                            return _client.get("/nodes/" + _node + "/storage/" + _storage + "/rrd", parameters);
                        }

                        /**
                         * Read storage RRD statistics (returns PNG).
                         *
                         * @param ds The list of datasources you want to
                         * display.
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         */
                        public JSONObject rrd(String ds, String timeframe) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("ds", ds);
                            parameters.put("timeframe", timeframe);
                            return _client.get("/nodes/" + _node + "/storage/" + _storage + "/rrd", parameters);
                        }
                    }

                    public class PVERrddata extends Base {

                        private Object _node;
                        private Object _storage;

                        protected PVERrddata(Client client, Object node, Object storage) {
                            _client = client;
                            _node = node;
                            _storage = storage;
                        }

                        /**
                         * Read storage RRD statistics.
                         *
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         * @param cf The RRD consolidation function Enum:
                         * AVERAGE,MAX
                         */
                        public JSONObject rrddata(String timeframe, String cf) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("timeframe", timeframe);
                            parameters.put("cf", cf);
                            return _client.get("/nodes/" + _node + "/storage/" + _storage + "/rrddata", parameters);
                        }

                        /**
                         * Read storage RRD statistics.
                         *
                         * @param timeframe Specify the time frame you are
                         * interested in. Enum: hour,day,week,month,year
                         */
                        public JSONObject rrddata(String timeframe) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("timeframe", timeframe);
                            return _client.get("/nodes/" + _node + "/storage/" + _storage + "/rrddata", parameters);
                        }
                    }

                    public class PVEUpload extends Base {

                        private Object _node;
                        private Object _storage;

                        protected PVEUpload(Client client, Object node, Object storage) {
                            _client = client;
                            _node = node;
                            _storage = storage;
                        }

                        /**
                         * Upload templates and ISO images.
                         *
                         * @param content Content type.
                         * @param filename The name of the file to create.
                         * @param tmpfilename The source file name. This
                         * parameter is usually set by the REST handler. You can
                         * only overwrite it when connecting to the trustet port
                         * on localhost.
                         */
                        public JSONObject upload(String content, String filename, String tmpfilename) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("content", content);
                            parameters.put("filename", filename);
                            parameters.put("tmpfilename", tmpfilename);
                            return _client.post("/nodes/" + _node + "/storage/" + _storage + "/upload", parameters);
                        }

                        /**
                         * Upload templates and ISO images.
                         *
                         * @param content Content type.
                         * @param filename The name of the file to create.
                         */
                        public JSONObject upload(String content, String filename) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("content", content);
                            parameters.put("filename", filename);
                            return _client.post("/nodes/" + _node + "/storage/" + _storage + "/upload", parameters);
                        }
                    }

                    /**
                     *
                     */
                    public JSONObject diridx() throws JSONException {
                        return _client.get("/nodes/" + _node + "/storage/" + _storage + "", null);
                    }
                }

                /**
                 * Get status for all datastores.
                 *
                 * @param content Only list stores which support this content
                 * type.
                 * @param enabled Only list stores which are enabled (not
                 * disabled in config).
                 * @param storage Only list status for specified storage
                 * @param target If target is different to 'node', we only lists
                 * shared storages which content is accessible on this 'node'
                 * and the specified 'target' node.
                 */
                public JSONObject index(String content, Boolean enabled, String storage, String target) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("content", content);
                    parameters.put("enabled", enabled);
                    parameters.put("storage", storage);
                    parameters.put("target", target);
                    return _client.get("/nodes/" + _node + "/storage", parameters);
                }

                /**
                 * Get status for all datastores.
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/nodes/" + _node + "/storage", null);
                }
            }

            public class PVEDisks extends Base {

                private Object _node;

                protected PVEDisks(Client client, Object node) {
                    _client = client;
                    _node = node;
                }
                private PVEList _list;

                public PVEList getList() {
                    if (_list == null) {
                        _list = new PVEList(_client, _node);
                    }
                    return _list;
                }
                private PVESmart _smart;

                public PVESmart getSmart() {
                    if (_smart == null) {
                        _smart = new PVESmart(_client, _node);
                    }
                    return _smart;
                }
                private PVEInitgpt _initgpt;

                public PVEInitgpt getInitgpt() {
                    if (_initgpt == null) {
                        _initgpt = new PVEInitgpt(_client, _node);
                    }
                    return _initgpt;
                }

                public class PVEList extends Base {

                    private Object _node;

                    protected PVEList(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * List local disks.
                     */
                    public JSONObject list() throws JSONException {
                        return _client.get("/nodes/" + _node + "/disks/list", null);
                    }
                }

                public class PVESmart extends Base {

                    private Object _node;

                    protected PVESmart(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Get SMART Health of a disk.
                     *
                     * @param disk Block device name
                     * @param healthonly If true returns only the health status
                     */
                    public JSONObject smart(String disk, Boolean healthonly) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("disk", disk);
                        parameters.put("healthonly", healthonly);
                        return _client.get("/nodes/" + _node + "/disks/smart", parameters);
                    }

                    /**
                     * Get SMART Health of a disk.
                     *
                     * @param disk Block device name
                     */
                    public JSONObject smart(String disk) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("disk", disk);
                        return _client.get("/nodes/" + _node + "/disks/smart", parameters);
                    }
                }

                public class PVEInitgpt extends Base {

                    private Object _node;

                    protected PVEInitgpt(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Initialize Disk with GPT
                     *
                     * @param disk Block device name
                     * @param uuid UUID for the GPT table
                     */
                    public JSONObject initgpt(String disk, String uuid) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("disk", disk);
                        parameters.put("uuid", uuid);
                        return _client.post("/nodes/" + _node + "/disks/initgpt", parameters);
                    }

                    /**
                     * Initialize Disk with GPT
                     *
                     * @param disk Block device name
                     */
                    public JSONObject initgpt(String disk) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("disk", disk);
                        return _client.post("/nodes/" + _node + "/disks/initgpt", parameters);
                    }
                }

                /**
                 * Node index.
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/nodes/" + _node + "/disks", null);
                }
            }

            public class PVEApt extends Base {

                private Object _node;

                protected PVEApt(Client client, Object node) {
                    _client = client;
                    _node = node;
                }
                private PVEUpdate _update;

                public PVEUpdate getUpdate() {
                    if (_update == null) {
                        _update = new PVEUpdate(_client, _node);
                    }
                    return _update;
                }
                private PVEChangelog _changelog;

                public PVEChangelog getChangelog() {
                    if (_changelog == null) {
                        _changelog = new PVEChangelog(_client, _node);
                    }
                    return _changelog;
                }
                private PVEVersions _versions;

                public PVEVersions getVersions() {
                    if (_versions == null) {
                        _versions = new PVEVersions(_client, _node);
                    }
                    return _versions;
                }

                public class PVEUpdate extends Base {

                    private Object _node;

                    protected PVEUpdate(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * List available updates.
                     */
                    public JSONObject listUpdates() throws JSONException {
                        return _client.get("/nodes/" + _node + "/apt/update", null);
                    }

                    /**
                     * This is used to resynchronize the package index files
                     * from their sources (apt-get update).
                     *
                     * @param notify Send notification mail about new packages
                     * (to email address specified for user 'root@pam').
                     * @param quiet Only produces output suitable for logging,
                     * omitting progress indicators.
                     */
                    public JSONObject updateDatabase(Boolean notify, Boolean quiet) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("notify", notify);
                        parameters.put("quiet", quiet);
                        return _client.post("/nodes/" + _node + "/apt/update", parameters);
                    }

                    /**
                     * This is used to resynchronize the package index files
                     * from their sources (apt-get update).
                     */
                    public JSONObject updateDatabase() throws JSONException {
                        return _client.post("/nodes/" + _node + "/apt/update", null);
                    }
                }

                public class PVEChangelog extends Base {

                    private Object _node;

                    protected PVEChangelog(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Get package changelogs.
                     *
                     * @param name Package name.
                     * @param version Package version.
                     */
                    public JSONObject changelog(String name, String version) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("name", name);
                        parameters.put("version", version);
                        return _client.get("/nodes/" + _node + "/apt/changelog", parameters);
                    }

                    /**
                     * Get package changelogs.
                     *
                     * @param name Package name.
                     */
                    public JSONObject changelog(String name) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("name", name);
                        return _client.get("/nodes/" + _node + "/apt/changelog", parameters);
                    }
                }

                public class PVEVersions extends Base {

                    private Object _node;

                    protected PVEVersions(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Get package information for important Proxmox packages.
                     */
                    public JSONObject versions() throws JSONException {
                        return _client.get("/nodes/" + _node + "/apt/versions", null);
                    }
                }

                /**
                 * Directory index for apt (Advanced Package Tool).
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/nodes/" + _node + "/apt", null);
                }
            }

            public class PVEFirewall extends Base {

                private Object _node;

                protected PVEFirewall(Client client, Object node) {
                    _client = client;
                    _node = node;
                }
                private PVERules _rules;

                public PVERules getRules() {
                    if (_rules == null) {
                        _rules = new PVERules(_client, _node);
                    }
                    return _rules;
                }
                private PVEOptions _options;

                public PVEOptions getOptions() {
                    if (_options == null) {
                        _options = new PVEOptions(_client, _node);
                    }
                    return _options;
                }
                private PVELog _log;

                public PVELog getLog() {
                    if (_log == null) {
                        _log = new PVELog(_client, _node);
                    }
                    return _log;
                }

                public class PVERules extends Base {

                    private Object _node;

                    protected PVERules(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    public PVEItemPos get(Object pos) {
                        return new PVEItemPos(_client, _node, pos);
                    }

                    public class PVEItemPos extends Base {

                        private Object _node;
                        private Object _pos;

                        protected PVEItemPos(Client client, Object node, Object pos) {
                            _client = client;
                            _node = node;
                            _pos = pos;
                        }

                        /**
                         * Delete rule.
                         *
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         */
                        public void deleteRule(String digest) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("digest", digest);
                            _client.delete("/nodes/" + _node + "/firewall/rules/" + _pos + "", parameters);
                        }

                        /**
                         * Delete rule.
                         */
                        public void deleteRule() throws JSONException {
                            _client.delete("/nodes/" + _node + "/firewall/rules/" + _pos + "", null);
                        }

                        /**
                         * Get single rule data.
                         */
                        public JSONObject getRule() throws JSONException {
                            return _client.get("/nodes/" + _node + "/firewall/rules/" + _pos + "", null);
                        }

                        /**
                         * Modify rule data.
                         *
                         * @param action Rule action ('ACCEPT', 'DROP',
                         * 'REJECT') or security group name.
                         * @param comment Descriptive comment.
                         * @param delete A list of settings you want to delete.
                         * @param dest Restrict packet destination address. This
                         * can refer to a single IP address, an IP set
                         * ('+ipsetname') or an IP alias definition. You can
                         * also specify an address range like
                         * '20.34.101.207-201.3.9.99', or a list of IP addresses
                         * and networks (entries are separated by comma). Please
                         * do not mix IPv4 and IPv6 addresses inside such lists.
                         * @param digest Prevent changes if current
                         * configuration file has different SHA1 digest. This
                         * can be used to prevent concurrent modifications.
                         * @param dport Restrict TCP/UDP destination port. You
                         * can use service names or simple numbers (0-65535), as
                         * defined in '/etc/services'. Port ranges can be
                         * specified with '\d+:\d+', for example '80:85', and
                         * you can use comma separated list to match several
                         * ports or ranges.
                         * @param enable Flag to enable/disable a rule.
                         * @param iface Network interface name. You have to use
                         * network configuration key names for VMs and
                         * containers ('net\d+'). Host related rules can use
                         * arbitrary strings.
                         * @param macro Use predefined standard macro.
                         * @param moveto Move rule to new position
                         * &amp;lt;moveto&amp;gt;. Other arguments are ignored.
                         * @param proto IP protocol. You can use protocol names
                         * ('tcp'/'udp') or simple numbers, as defined in
                         * '/etc/protocols'.
                         * @param source Restrict packet source address. This
                         * can refer to a single IP address, an IP set
                         * ('+ipsetname') or an IP alias definition. You can
                         * also specify an address range like
                         * '20.34.101.207-201.3.9.99', or a list of IP addresses
                         * and networks (entries are separated by comma). Please
                         * do not mix IPv4 and IPv6 addresses inside such lists.
                         * @param sport Restrict TCP/UDP source port. You can
                         * use service names or simple numbers (0-65535), as
                         * defined in '/etc/services'. Port ranges can be
                         * specified with '\d+:\d+', for example '80:85', and
                         * you can use comma separated list to match several
                         * ports or ranges.
                         * @param type Rule type. Enum: in,out,group
                         */
                        public void updateRule(String action, String comment, String delete, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer moveto, String proto, String source, String sport, String type) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("action", action);
                            parameters.put("comment", comment);
                            parameters.put("delete", delete);
                            parameters.put("dest", dest);
                            parameters.put("digest", digest);
                            parameters.put("dport", dport);
                            parameters.put("enable", enable);
                            parameters.put("iface", iface);
                            parameters.put("macro", macro);
                            parameters.put("moveto", moveto);
                            parameters.put("proto", proto);
                            parameters.put("source", source);
                            parameters.put("sport", sport);
                            parameters.put("type", type);
                            _client.put("/nodes/" + _node + "/firewall/rules/" + _pos + "", parameters);
                        }

                        /**
                         * Modify rule data.
                         */
                        public void updateRule() throws JSONException {
                            _client.put("/nodes/" + _node + "/firewall/rules/" + _pos + "", null);
                        }
                    }

                    /**
                     * List rules.
                     */
                    public JSONObject getRules() throws JSONException {
                        return _client.get("/nodes/" + _node + "/firewall/rules", null);
                    }

                    /**
                     * Create new rule.
                     *
                     * @param action Rule action ('ACCEPT', 'DROP', 'REJECT') or
                     * security group name.
                     * @param type Rule type. Enum: in,out,group
                     * @param comment Descriptive comment.
                     * @param dest Restrict packet destination address. This can
                     * refer to a single IP address, an IP set ('+ipsetname') or
                     * an IP alias definition. You can also specify an address
                     * range like '20.34.101.207-201.3.9.99', or a list of IP
                     * addresses and networks (entries are separated by comma).
                     * Please do not mix IPv4 and IPv6 addresses inside such
                     * lists.
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     * @param dport Restrict TCP/UDP destination port. You can
                     * use service names or simple numbers (0-65535), as defined
                     * in '/etc/services'. Port ranges can be specified with
                     * '\d+:\d+', for example '80:85', and you can use comma
                     * separated list to match several ports or ranges.
                     * @param enable Flag to enable/disable a rule.
                     * @param iface Network interface name. You have to use
                     * network configuration key names for VMs and containers
                     * ('net\d+'). Host related rules can use arbitrary strings.
                     * @param macro Use predefined standard macro.
                     * @param pos Update rule at position &amp;lt;pos&amp;gt;.
                     * @param proto IP protocol. You can use protocol names
                     * ('tcp'/'udp') or simple numbers, as defined in
                     * '/etc/protocols'.
                     * @param source Restrict packet source address. This can
                     * refer to a single IP address, an IP set ('+ipsetname') or
                     * an IP alias definition. You can also specify an address
                     * range like '20.34.101.207-201.3.9.99', or a list of IP
                     * addresses and networks (entries are separated by comma).
                     * Please do not mix IPv4 and IPv6 addresses inside such
                     * lists.
                     * @param sport Restrict TCP/UDP source port. You can use
                     * service names or simple numbers (0-65535), as defined in
                     * '/etc/services'. Port ranges can be specified with
                     * '\d+:\d+', for example '80:85', and you can use comma
                     * separated list to match several ports or ranges.
                     */
                    public void createRule(String action, String type, String comment, String dest, String digest, String dport, Integer enable, String iface, String macro, Integer pos, String proto, String source, String sport) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("action", action);
                        parameters.put("type", type);
                        parameters.put("comment", comment);
                        parameters.put("dest", dest);
                        parameters.put("digest", digest);
                        parameters.put("dport", dport);
                        parameters.put("enable", enable);
                        parameters.put("iface", iface);
                        parameters.put("macro", macro);
                        parameters.put("pos", pos);
                        parameters.put("proto", proto);
                        parameters.put("source", source);
                        parameters.put("sport", sport);
                        _client.post("/nodes/" + _node + "/firewall/rules", parameters);
                    }

                    /**
                     * Create new rule.
                     *
                     * @param action Rule action ('ACCEPT', 'DROP', 'REJECT') or
                     * security group name.
                     * @param type Rule type. Enum: in,out,group
                     */
                    public void createRule(String action, String type) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("action", action);
                        parameters.put("type", type);
                        _client.post("/nodes/" + _node + "/firewall/rules", parameters);
                    }
                }

                public class PVEOptions extends Base {

                    private Object _node;

                    protected PVEOptions(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Get host firewall options.
                     */
                    public JSONObject getOptions() throws JSONException {
                        return _client.get("/nodes/" + _node + "/firewall/options", null);
                    }

                    /**
                     * Set Firewall options.
                     *
                     * @param delete A list of settings you want to delete.
                     * @param digest Prevent changes if current configuration
                     * file has different SHA1 digest. This can be used to
                     * prevent concurrent modifications.
                     * @param enable Enable host firewall rules.
                     * @param log_level_in Log level for incoming traffic. Enum:
                     * emerg,alert,crit,err,warning,notice,info,debug,nolog
                     * @param log_level_out Log level for outgoing traffic.
                     * Enum:
                     * emerg,alert,crit,err,warning,notice,info,debug,nolog
                     * @param ndp Enable NDP.
                     * @param nf_conntrack_max Maximum number of tracked
                     * connections.
                     * @param nf_conntrack_tcp_timeout_established Conntrack
                     * established timeout.
                     * @param nosmurfs Enable SMURFS filter.
                     * @param smurf_log_level Log level for SMURFS filter. Enum:
                     * emerg,alert,crit,err,warning,notice,info,debug,nolog
                     * @param tcp_flags_log_level Log level for illegal tcp
                     * flags filter. Enum:
                     * emerg,alert,crit,err,warning,notice,info,debug,nolog
                     * @param tcpflags Filter illegal combinations of TCP flags.
                     */
                    public void setOptions(String delete, String digest, Boolean enable, String log_level_in, String log_level_out, Boolean ndp, Integer nf_conntrack_max, Integer nf_conntrack_tcp_timeout_established, Boolean nosmurfs, String smurf_log_level, String tcp_flags_log_level, Boolean tcpflags) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("delete", delete);
                        parameters.put("digest", digest);
                        parameters.put("enable", enable);
                        parameters.put("log_level_in", log_level_in);
                        parameters.put("log_level_out", log_level_out);
                        parameters.put("ndp", ndp);
                        parameters.put("nf_conntrack_max", nf_conntrack_max);
                        parameters.put("nf_conntrack_tcp_timeout_established", nf_conntrack_tcp_timeout_established);
                        parameters.put("nosmurfs", nosmurfs);
                        parameters.put("smurf_log_level", smurf_log_level);
                        parameters.put("tcp_flags_log_level", tcp_flags_log_level);
                        parameters.put("tcpflags", tcpflags);
                        _client.put("/nodes/" + _node + "/firewall/options", parameters);
                    }

                    /**
                     * Set Firewall options.
                     */
                    public void setOptions() throws JSONException {
                        _client.put("/nodes/" + _node + "/firewall/options", null);
                    }
                }

                public class PVELog extends Base {

                    private Object _node;

                    protected PVELog(Client client, Object node) {
                        _client = client;
                        _node = node;
                    }

                    /**
                     * Read firewall log
                     *
                     * @param limit
                     * @param start
                     */
                    public JSONObject log(Integer limit, Integer start) throws JSONException {
                        Map<String, Object> parameters = new HashMap<String, Object>();
                        parameters.put("limit", limit);
                        parameters.put("start", start);
                        return _client.get("/nodes/" + _node + "/firewall/log", parameters);
                    }

                    /**
                     * Read firewall log
                     */
                    public JSONObject log() throws JSONException {
                        return _client.get("/nodes/" + _node + "/firewall/log", null);
                    }
                }

                /**
                 * Directory index.
                 */
                public JSONObject index() throws JSONException {
                    return _client.get("/nodes/" + _node + "/firewall", null);
                }
            }

            public class PVEReplication extends Base {

                private Object _node;

                protected PVEReplication(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                public PVEItemId get(Object id) {
                    return new PVEItemId(_client, _node, id);
                }

                public class PVEItemId extends Base {

                    private Object _node;
                    private Object _id;

                    protected PVEItemId(Client client, Object node, Object id) {
                        _client = client;
                        _node = node;
                        _id = id;
                    }
                    private PVEStatus _status;

                    public PVEStatus getStatus() {
                        if (_status == null) {
                            _status = new PVEStatus(_client, _node, _id);
                        }
                        return _status;
                    }
                    private PVELog _log;

                    public PVELog getLog() {
                        if (_log == null) {
                            _log = new PVELog(_client, _node, _id);
                        }
                        return _log;
                    }
                    private PVEScheduleNow _scheduleNow;

                    public PVEScheduleNow getScheduleNow() {
                        if (_scheduleNow == null) {
                            _scheduleNow = new PVEScheduleNow(_client, _node, _id);
                        }
                        return _scheduleNow;
                    }

                    public class PVEStatus extends Base {

                        private Object _node;
                        private Object _id;

                        protected PVEStatus(Client client, Object node, Object id) {
                            _client = client;
                            _node = node;
                            _id = id;
                        }

                        /**
                         * Get replication job status.
                         */
                        public JSONObject jobStatus() throws JSONException {
                            return _client.get("/nodes/" + _node + "/replication/" + _id + "/status", null);
                        }
                    }

                    public class PVELog extends Base {

                        private Object _node;
                        private Object _id;

                        protected PVELog(Client client, Object node, Object id) {
                            _client = client;
                            _node = node;
                            _id = id;
                        }

                        /**
                         * Read replication job log.
                         *
                         * @param limit
                         * @param start
                         */
                        public JSONObject readJobLog(Integer limit, Integer start) throws JSONException {
                            Map<String, Object> parameters = new HashMap<String, Object>();
                            parameters.put("limit", limit);
                            parameters.put("start", start);
                            return _client.get("/nodes/" + _node + "/replication/" + _id + "/log", parameters);
                        }

                        /**
                         * Read replication job log.
                         */
                        public JSONObject readJobLog() throws JSONException {
                            return _client.get("/nodes/" + _node + "/replication/" + _id + "/log", null);
                        }
                    }

                    public class PVEScheduleNow extends Base {

                        private Object _node;
                        private Object _id;

                        protected PVEScheduleNow(Client client, Object node, Object id) {
                            _client = client;
                            _node = node;
                            _id = id;
                        }

                        /**
                         * Schedule replication job to start as soon as
                         * possible.
                         */
                        public JSONObject scheduleNow() throws JSONException {
                            return _client.post("/nodes/" + _node + "/replication/" + _id + "/schedule_now", null);
                        }
                    }

                    /**
                     * Directory index.
                     */
                    public JSONObject index() throws JSONException {
                        return _client.get("/nodes/" + _node + "/replication/" + _id + "", null);
                    }
                }

                /**
                 * List status of all replication jobs on this node.
                 *
                 * @param guest Only list replication jobs for this guest.
                 */
                public JSONObject status(Integer guest) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("guest", guest);
                    return _client.get("/nodes/" + _node + "/replication", parameters);
                }

                /**
                 * List status of all replication jobs on this node.
                 */
                public JSONObject status() throws JSONException {
                    return _client.get("/nodes/" + _node + "/replication", null);
                }
            }

            public class PVEVersion extends Base {

                private Object _node;

                protected PVEVersion(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * API version details
                 */
                public JSONObject version() throws JSONException {
                    return _client.get("/nodes/" + _node + "/version", null);
                }
            }

            public class PVEStatus extends Base {

                private Object _node;

                protected PVEStatus(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Read node status
                 */
                public JSONObject status() throws JSONException {
                    return _client.get("/nodes/" + _node + "/status", null);
                }

                /**
                 * Reboot or shutdown a node.
                 *
                 * @param command Specify the command. Enum: reboot,shutdown
                 */
                public void nodeCmd(String command) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("command", command);
                    _client.post("/nodes/" + _node + "/status", parameters);
                }
            }

            public class PVENetstat extends Base {

                private Object _node;

                protected PVENetstat(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Read tap/vm network device interface counters
                 */
                public JSONObject netstat() throws JSONException {
                    return _client.get("/nodes/" + _node + "/netstat", null);
                }
            }

            public class PVEExecute extends Base {

                private Object _node;

                protected PVEExecute(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Execute multiple commands in order.
                 *
                 * @param commands JSON encoded array of commands.
                 */
                public JSONObject execute(String commands) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("commands", commands);
                    return _client.post("/nodes/" + _node + "/execute", parameters);
                }
            }

            public class PVERrd extends Base {

                private Object _node;

                protected PVERrd(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Read node RRD statistics (returns PNG)
                 *
                 * @param ds The list of datasources you want to display.
                 * @param timeframe Specify the time frame you are interested
                 * in. Enum: hour,day,week,month,year
                 * @param cf The RRD consolidation function Enum: AVERAGE,MAX
                 */
                public JSONObject rrd(String ds, String timeframe, String cf) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("ds", ds);
                    parameters.put("timeframe", timeframe);
                    parameters.put("cf", cf);
                    return _client.get("/nodes/" + _node + "/rrd", parameters);
                }

                /**
                 * Read node RRD statistics (returns PNG)
                 *
                 * @param ds The list of datasources you want to display.
                 * @param timeframe Specify the time frame you are interested
                 * in. Enum: hour,day,week,month,year
                 */
                public JSONObject rrd(String ds, String timeframe) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("ds", ds);
                    parameters.put("timeframe", timeframe);
                    return _client.get("/nodes/" + _node + "/rrd", parameters);
                }
            }

            public class PVERrddata extends Base {

                private Object _node;

                protected PVERrddata(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Read node RRD statistics
                 *
                 * @param timeframe Specify the time frame you are interested
                 * in. Enum: hour,day,week,month,year
                 * @param cf The RRD consolidation function Enum: AVERAGE,MAX
                 */
                public JSONObject rrddata(String timeframe, String cf) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("timeframe", timeframe);
                    parameters.put("cf", cf);
                    return _client.get("/nodes/" + _node + "/rrddata", parameters);
                }

                /**
                 * Read node RRD statistics
                 *
                 * @param timeframe Specify the time frame you are interested
                 * in. Enum: hour,day,week,month,year
                 */
                public JSONObject rrddata(String timeframe) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("timeframe", timeframe);
                    return _client.get("/nodes/" + _node + "/rrddata", parameters);
                }
            }

            public class PVESyslog extends Base {

                private Object _node;

                protected PVESyslog(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Read system log
                 *
                 * @param limit
                 * @param since Display all log since this date-time string.
                 * @param start
                 * @param until Display all log until this date-time string.
                 */
                public JSONObject syslog(Integer limit, String since, Integer start, String until) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("limit", limit);
                    parameters.put("since", since);
                    parameters.put("start", start);
                    parameters.put("until", until);
                    return _client.get("/nodes/" + _node + "/syslog", parameters);
                }

                /**
                 * Read system log
                 */
                public JSONObject syslog() throws JSONException {
                    return _client.get("/nodes/" + _node + "/syslog", null);
                }
            }

            public class PVEVncshell extends Base {

                private Object _node;

                protected PVEVncshell(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Creates a VNC Shell proxy.
                 *
                 * @param height sets the height of the console in pixels.
                 * @param upgrade Run 'apt-get dist-upgrade' instead of normal
                 * shell.
                 * @param websocket use websocket instead of standard vnc.
                 * @param width sets the width of the console in pixels.
                 */
                public JSONObject vncshell(Integer height, Boolean upgrade, Boolean websocket, Integer width) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("height", height);
                    parameters.put("upgrade", upgrade);
                    parameters.put("websocket", websocket);
                    parameters.put("width", width);
                    return _client.post("/nodes/" + _node + "/vncshell", parameters);
                }

                /**
                 * Creates a VNC Shell proxy.
                 */
                public JSONObject vncshell() throws JSONException {
                    return _client.post("/nodes/" + _node + "/vncshell", null);
                }
            }

            public class PVEVncwebsocket extends Base {

                private Object _node;

                protected PVEVncwebsocket(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Opens a weksocket for VNC traffic.
                 *
                 * @param port Port number returned by previous vncproxy call.
                 * @param vncticket Ticket from previous call to vncproxy.
                 */
                public JSONObject vncwebsocket(int port, String vncticket) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("port", port);
                    parameters.put("vncticket", vncticket);
                    return _client.get("/nodes/" + _node + "/vncwebsocket", parameters);
                }
            }

            public class PVESpiceshell extends Base {

                private Object _node;

                protected PVESpiceshell(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Creates a SPICE shell.
                 *
                 * @param proxy SPICE proxy server. This can be used by the
                 * client to specify the proxy server. All nodes in a cluster
                 * runs 'spiceproxy', so it is up to the client to choose one.
                 * By default, we return the node where the VM is currently
                 * running. As resonable setting is to use same node you use to
                 * connect to the API (This is window.location.hostname for the
                 * JS GUI).
                 * @param upgrade Run 'apt-get dist-upgrade' instead of normal
                 * shell.
                 */
                public JSONObject spiceshell(String proxy, Boolean upgrade) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("proxy", proxy);
                    parameters.put("upgrade", upgrade);
                    return _client.post("/nodes/" + _node + "/spiceshell", parameters);
                }

                /**
                 * Creates a SPICE shell.
                 */
                public JSONObject spiceshell() throws JSONException {
                    return _client.post("/nodes/" + _node + "/spiceshell", null);
                }
            }

            public class PVEDns extends Base {

                private Object _node;

                protected PVEDns(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Read DNS settings.
                 */
                public JSONObject dns() throws JSONException {
                    return _client.get("/nodes/" + _node + "/dns", null);
                }

                /**
                 * Write DNS settings.
                 *
                 * @param search Search domain for host-name lookup.
                 * @param dns1 First name server IP address.
                 * @param dns2 Second name server IP address.
                 * @param dns3 Third name server IP address.
                 */
                public void updateDns(String search, String dns1, String dns2, String dns3) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("search", search);
                    parameters.put("dns1", dns1);
                    parameters.put("dns2", dns2);
                    parameters.put("dns3", dns3);
                    _client.put("/nodes/" + _node + "/dns", parameters);
                }

                /**
                 * Write DNS settings.
                 *
                 * @param search Search domain for host-name lookup.
                 */
                public void updateDns(String search) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("search", search);
                    _client.put("/nodes/" + _node + "/dns", parameters);
                }
            }

            public class PVETime extends Base {

                private Object _node;

                protected PVETime(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Read server time and time zone settings.
                 */
                public JSONObject time() throws JSONException {
                    return _client.get("/nodes/" + _node + "/time", null);
                }

                /**
                 * Set time zone.
                 *
                 * @param timezone Time zone. The file
                 * '/usr/share/zoneinfo/zone.tab' contains the list of valid
                 * names.
                 */
                public void setTimezone(String timezone) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("timezone", timezone);
                    _client.put("/nodes/" + _node + "/time", parameters);
                }
            }

            public class PVEAplinfo extends Base {

                private Object _node;

                protected PVEAplinfo(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Get list of appliances.
                 */
                public JSONObject aplinfo() throws JSONException {
                    return _client.get("/nodes/" + _node + "/aplinfo", null);
                }

                /**
                 * Download appliance templates.
                 *
                 * @param storage The storage where the template will be stored
                 * @param template The template wich will downloaded
                 */
                public JSONObject aplDownload(String storage, String template) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("storage", storage);
                    parameters.put("template", template);
                    return _client.post("/nodes/" + _node + "/aplinfo", parameters);
                }
            }

            public class PVEReport extends Base {

                private Object _node;

                protected PVEReport(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Gather various systems information about a node
                 */
                public JSONObject report() throws JSONException {
                    return _client.get("/nodes/" + _node + "/report", null);
                }
            }

            public class PVEStartall extends Base {

                private Object _node;

                protected PVEStartall(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Start all VMs and containers (when onboot=1).
                 *
                 * @param force force if onboot=0.
                 * @param vms Only consider Guests with these IDs.
                 */
                public JSONObject startall(Boolean force, String vms) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("force", force);
                    parameters.put("vms", vms);
                    return _client.post("/nodes/" + _node + "/startall", parameters);
                }

                /**
                 * Start all VMs and containers (when onboot=1).
                 */
                public JSONObject startall() throws JSONException {
                    return _client.post("/nodes/" + _node + "/startall", null);
                }
            }

            public class PVEStopall extends Base {

                private Object _node;

                protected PVEStopall(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Stop all VMs and Containers.
                 *
                 * @param vms Only consider Guests with these IDs.
                 */
                public JSONObject stopall(String vms) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("vms", vms);
                    return _client.post("/nodes/" + _node + "/stopall", parameters);
                }

                /**
                 * Stop all VMs and Containers.
                 */
                public JSONObject stopall() throws JSONException {
                    return _client.post("/nodes/" + _node + "/stopall", null);
                }
            }

            public class PVEMigrateall extends Base {

                private Object _node;

                protected PVEMigrateall(Client client, Object node) {
                    _client = client;
                    _node = node;
                }

                /**
                 * Migrate all VMs and Containers.
                 *
                 * @param target Target node.
                 * @param maxworkers Maximal number of parallel migration job.
                 * If not set use 'max_workers' from datacenter.cfg, one of both
                 * must be set!
                 * @param vms Only consider Guests with these IDs.
                 */
                public JSONObject migrateall(String target, Integer maxworkers, String vms) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("target", target);
                    parameters.put("maxworkers", maxworkers);
                    parameters.put("vms", vms);
                    return _client.post("/nodes/" + _node + "/migrateall", parameters);
                }

                /**
                 * Migrate all VMs and Containers.
                 *
                 * @param target Target node.
                 */
                public JSONObject migrateall(String target) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("target", target);
                    return _client.post("/nodes/" + _node + "/migrateall", parameters);
                }
            }

            /**
             * Node index.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/nodes/" + _node + "", null);
            }
        }

        /**
         * Cluster node index.
         */
        public JSONObject index() throws JSONException {
            return _client.get("/nodes", null);
        }
    }

    public class PVEStorage extends Base {

        protected PVEStorage(Client client) {
            _client = client;
        }

        public PVEItemStorage get(Object storage) {
            return new PVEItemStorage(_client, storage);
        }

        public class PVEItemStorage extends Base {

            private Object _storage;

            protected PVEItemStorage(Client client, Object storage) {
                _client = client;
                _storage = storage;
            }

            /**
             * Delete storage configuration.
             */
            public void delete() throws JSONException {
                _client.delete("/storage/" + _storage + "", null);
            }

            /**
             * Read storage configuration.
             */
            public JSONObject read() throws JSONException {
                return _client.get("/storage/" + _storage + "", null);
            }

            /**
             * Update storage configuration.
             *
             * @param blocksize block size
             * @param comstar_hg host group for comstar views
             * @param comstar_tg target group for comstar views
             * @param content Allowed content types. NOTE: the value 'rootdir'
             * is used for Containers, and value 'images' for VMs.
             * @param delete A list of settings you want to delete.
             * @param digest Prevent changes if current configuration file has
             * different SHA1 digest. This can be used to prevent concurrent
             * modifications.
             * @param disable Flag to disable the storage.
             * @param format Default image format.
             * @param is_mountpoint Assume the directory is an externally
             * managed mountpoint. If nothing is mounted the storage will be
             * considered offline.
             * @param krbd Access rbd through krbd kernel module.
             * @param maxfiles Maximal number of backup files per VM. Use '0'
             * for unlimted.
             * @param mkdir Create the directory if it doesn't exist.
             * @param nodes List of cluster node names.
             * @param nowritecache disable write caching on the target
             * @param options NFS mount options (see 'man nfs')
             * @param pool Pool.
             * @param redundancy The redundancy count specifies the number of
             * nodes to which the resource should be deployed. It must be at
             * least 1 and at most the number of nodes in the cluster.
             * @param saferemove Zero-out data when removing LVs.
             * @param saferemove_throughput Wipe throughput (cstream -t
             * parameter value).
             * @param server Server IP or DNS name.
             * @param server2 Backup volfile server IP or DNS name.
             * @param shared Mark storage as shared.
             * @param sparse use sparse volumes
             * @param tagged_only Only use logical volumes tagged with
             * 'pve-vm-ID'.
             * @param transport Gluster transport: tcp or rdma Enum:
             * tcp,rdma,unix
             * @param username RBD Id.
             */
            public void update(String blocksize, String comstar_hg, String comstar_tg, String content, String delete, String digest, Boolean disable, String format, Boolean is_mountpoint, Boolean krbd, Integer maxfiles, Boolean mkdir, String nodes, Boolean nowritecache, String options, String pool, Integer redundancy, Boolean saferemove, String saferemove_throughput, String server, String server2, Boolean shared, Boolean sparse, Boolean tagged_only, String transport, String username) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("blocksize", blocksize);
                parameters.put("comstar_hg", comstar_hg);
                parameters.put("comstar_tg", comstar_tg);
                parameters.put("content", content);
                parameters.put("delete", delete);
                parameters.put("digest", digest);
                parameters.put("disable", disable);
                parameters.put("format", format);
                parameters.put("is_mountpoint", is_mountpoint);
                parameters.put("krbd", krbd);
                parameters.put("maxfiles", maxfiles);
                parameters.put("mkdir", mkdir);
                parameters.put("nodes", nodes);
                parameters.put("nowritecache", nowritecache);
                parameters.put("options", options);
                parameters.put("pool", pool);
                parameters.put("redundancy", redundancy);
                parameters.put("saferemove", saferemove);
                parameters.put("saferemove_throughput", saferemove_throughput);
                parameters.put("server", server);
                parameters.put("server2", server2);
                parameters.put("shared", shared);
                parameters.put("sparse", sparse);
                parameters.put("tagged_only", tagged_only);
                parameters.put("transport", transport);
                parameters.put("username", username);
                _client.put("/storage/" + _storage + "", parameters);
            }

            /**
             * Update storage configuration.
             */
            public void update() throws JSONException {
                _client.put("/storage/" + _storage + "", null);
            }
        }

        /**
         * Storage index.
         *
         * @param type Only list storage of specific type Enum:
         * dir,drbd,glusterfs,iscsi,iscsidirect,lvm,lvmthin,nfs,rbd,sheepdog,zfs,zfspool
         */
        public JSONObject index(String type) throws JSONException {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("type", type);
            return _client.get("/storage", parameters);
        }

        /**
         * Storage index.
         */
        public JSONObject index() throws JSONException {
            return _client.get("/storage", null);
        }

        /**
         * Create a new storage.
         *
         * @param storage The storage identifier.
         * @param type Storage type. Enum:
         * dir,drbd,glusterfs,iscsi,iscsidirect,lvm,lvmthin,nfs,rbd,sheepdog,zfs,zfspool
         * @param authsupported Authsupported.
         * @param base_ Base volume. This volume is automatically activated.
         * @param blocksize block size
         * @param comstar_hg host group for comstar views
         * @param comstar_tg target group for comstar views
         * @param content Allowed content types. NOTE: the value 'rootdir' is
         * used for Containers, and value 'images' for VMs.
         * @param disable Flag to disable the storage.
         * @param export NFS export path.
         * @param format Default image format.
         * @param is_mountpoint Assume the directory is an externally managed
         * mountpoint. If nothing is mounted the storage will be considered
         * offline.
         * @param iscsiprovider iscsi provider
         * @param krbd Access rbd through krbd kernel module.
         * @param maxfiles Maximal number of backup files per VM. Use '0' for
         * unlimted.
         * @param mkdir Create the directory if it doesn't exist.
         * @param monhost Monitors daemon ips.
         * @param nodes List of cluster node names.
         * @param nowritecache disable write caching on the target
         * @param options NFS mount options (see 'man nfs')
         * @param path File system path.
         * @param pool Pool.
         * @param portal iSCSI portal (IP or DNS name with optional port).
         * @param redundancy The redundancy count specifies the number of nodes
         * to which the resource should be deployed. It must be at least 1 and
         * at most the number of nodes in the cluster.
         * @param saferemove Zero-out data when removing LVs.
         * @param saferemove_throughput Wipe throughput (cstream -t parameter
         * value).
         * @param server Server IP or DNS name.
         * @param server2 Backup volfile server IP or DNS name.
         * @param shared Mark storage as shared.
         * @param sparse use sparse volumes
         * @param tagged_only Only use logical volumes tagged with 'pve-vm-ID'.
         * @param target iSCSI target.
         * @param thinpool LVM thin pool LV name.
         * @param transport Gluster transport: tcp or rdma Enum: tcp,rdma,unix
         * @param username RBD Id.
         * @param vgname Volume group name.
         * @param volume Glusterfs Volume.
         */
        public void create(String storage, String type, String authsupported, String base_, String blocksize, String comstar_hg, String comstar_tg, String content, Boolean disable, String export, String format, Boolean is_mountpoint, String iscsiprovider, Boolean krbd, Integer maxfiles, Boolean mkdir, String monhost, String nodes, Boolean nowritecache, String options, String path, String pool, String portal, Integer redundancy, Boolean saferemove, String saferemove_throughput, String server, String server2, Boolean shared, Boolean sparse, Boolean tagged_only, String target, String thinpool, String transport, String username, String vgname, String volume) throws JSONException {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("storage", storage);
            parameters.put("type", type);
            parameters.put("authsupported", authsupported);
            parameters.put("base", base_);
            parameters.put("blocksize", blocksize);
            parameters.put("comstar_hg", comstar_hg);
            parameters.put("comstar_tg", comstar_tg);
            parameters.put("content", content);
            parameters.put("disable", disable);
            parameters.put("export", export);
            parameters.put("format", format);
            parameters.put("is_mountpoint", is_mountpoint);
            parameters.put("iscsiprovider", iscsiprovider);
            parameters.put("krbd", krbd);
            parameters.put("maxfiles", maxfiles);
            parameters.put("mkdir", mkdir);
            parameters.put("monhost", monhost);
            parameters.put("nodes", nodes);
            parameters.put("nowritecache", nowritecache);
            parameters.put("options", options);
            parameters.put("path", path);
            parameters.put("pool", pool);
            parameters.put("portal", portal);
            parameters.put("redundancy", redundancy);
            parameters.put("saferemove", saferemove);
            parameters.put("saferemove_throughput", saferemove_throughput);
            parameters.put("server", server);
            parameters.put("server2", server2);
            parameters.put("shared", shared);
            parameters.put("sparse", sparse);
            parameters.put("tagged_only", tagged_only);
            parameters.put("target", target);
            parameters.put("thinpool", thinpool);
            parameters.put("transport", transport);
            parameters.put("username", username);
            parameters.put("vgname", vgname);
            parameters.put("volume", volume);
            _client.post("/storage", parameters);
        }

        /**
         * Create a new storage.
         *
         * @param storage The storage identifier.
         * @param type Storage type. Enum:
         * dir,drbd,glusterfs,iscsi,iscsidirect,lvm,lvmthin,nfs,rbd,sheepdog,zfs,zfspool
         */
        public void create(String storage, String type) throws JSONException {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("storage", storage);
            parameters.put("type", type);
            _client.post("/storage", parameters);
        }
    }

    public class PVEAccess extends Base {

        protected PVEAccess(Client client) {
            _client = client;
        }
        private PVEUsers _users;

        public PVEUsers getUsers() {
            if (_users == null) {
                _users = new PVEUsers(_client);
            }
            return _users;
        }
        private PVEGroups _groups;

        public PVEGroups getGroups() {
            if (_groups == null) {
                _groups = new PVEGroups(_client);
            }
            return _groups;
        }
        private PVERoles _roles;

        public PVERoles getRoles() {
            if (_roles == null) {
                _roles = new PVERoles(_client);
            }
            return _roles;
        }
        private PVEAcl _acl;

        public PVEAcl getAcl() {
            if (_acl == null) {
                _acl = new PVEAcl(_client);
            }
            return _acl;
        }
        private PVEDomains _domains;

        public PVEDomains getDomains() {
            if (_domains == null) {
                _domains = new PVEDomains(_client);
            }
            return _domains;
        }
        private PVETicket _ticket;

        public PVETicket getTicket() {
            if (_ticket == null) {
                _ticket = new PVETicket(_client);
            }
            return _ticket;
        }
        private PVEPassword _password;

        public PVEPassword getPassword() {
            if (_password == null) {
                _password = new PVEPassword(_client);
            }
            return _password;
        }

        public class PVEUsers extends Base {

            protected PVEUsers(Client client) {
                _client = client;
            }

            public PVEItemUserid get(Object userid) {
                return new PVEItemUserid(_client, userid);
            }

            public class PVEItemUserid extends Base {

                private Object _userid;

                protected PVEItemUserid(Client client, Object userid) {
                    _client = client;
                    _userid = userid;
                }

                /**
                 * Delete user.
                 */
                public void deleteUser() throws JSONException {
                    _client.delete("/access/users/" + _userid + "", null);
                }

                /**
                 * Get user configuration.
                 */
                public JSONObject readUser() throws JSONException {
                    return _client.get("/access/users/" + _userid + "", null);
                }

                /**
                 * Update user configuration.
                 *
                 * @param append
                 * @param comment
                 * @param email
                 * @param enable Enable/disable the account.
                 * @param expire Account expiration date (seconds since epoch).
                 * '0' means no expiration date.
                 * @param firstname
                 * @param groups
                 * @param keys Keys for two factor auth (yubico).
                 * @param lastname
                 */
                public void updateUser(Boolean append, String comment, String email, Boolean enable, Integer expire, String firstname, String groups, String keys, String lastname) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("append", append);
                    parameters.put("comment", comment);
                    parameters.put("email", email);
                    parameters.put("enable", enable);
                    parameters.put("expire", expire);
                    parameters.put("firstname", firstname);
                    parameters.put("groups", groups);
                    parameters.put("keys", keys);
                    parameters.put("lastname", lastname);
                    _client.put("/access/users/" + _userid + "", parameters);
                }

                /**
                 * Update user configuration.
                 */
                public void updateUser() throws JSONException {
                    _client.put("/access/users/" + _userid + "", null);
                }
            }

            /**
             * User index.
             *
             * @param enabled Optional filter for enable property.
             */
            public JSONObject index(Boolean enabled) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("enabled", enabled);
                return _client.get("/access/users", parameters);
            }

            /**
             * User index.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/access/users", null);
            }

            /**
             * Create new user.
             *
             * @param userid User ID
             * @param comment
             * @param email
             * @param enable Enable the account (default). You can set this to
             * '0' to disable the accout
             * @param expire Account expiration date (seconds since epoch). '0'
             * means no expiration date.
             * @param firstname
             * @param groups
             * @param keys Keys for two factor auth (yubico).
             * @param lastname
             * @param password Initial password.
             */
            public void createUser(String userid, String comment, String email, Boolean enable, Integer expire, String firstname, String groups, String keys, String lastname, String password) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("userid", userid);
                parameters.put("comment", comment);
                parameters.put("email", email);
                parameters.put("enable", enable);
                parameters.put("expire", expire);
                parameters.put("firstname", firstname);
                parameters.put("groups", groups);
                parameters.put("keys", keys);
                parameters.put("lastname", lastname);
                parameters.put("password", password);
                _client.post("/access/users", parameters);
            }

            /**
             * Create new user.
             *
             * @param userid User ID
             */
            public void createUser(String userid) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("userid", userid);
                _client.post("/access/users", parameters);
            }
        }

        public class PVEGroups extends Base {

            protected PVEGroups(Client client) {
                _client = client;
            }

            public PVEItemGroupid get(Object groupid) {
                return new PVEItemGroupid(_client, groupid);
            }

            public class PVEItemGroupid extends Base {

                private Object _groupid;

                protected PVEItemGroupid(Client client, Object groupid) {
                    _client = client;
                    _groupid = groupid;
                }

                /**
                 * Delete group.
                 */
                public void deleteGroup() throws JSONException {
                    _client.delete("/access/groups/" + _groupid + "", null);
                }

                /**
                 * Get group configuration.
                 */
                public JSONObject readGroup() throws JSONException {
                    return _client.get("/access/groups/" + _groupid + "", null);
                }

                /**
                 * Update group data.
                 *
                 * @param comment
                 */
                public void updateGroup(String comment) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("comment", comment);
                    _client.put("/access/groups/" + _groupid + "", parameters);
                }

                /**
                 * Update group data.
                 */
                public void updateGroup() throws JSONException {
                    _client.put("/access/groups/" + _groupid + "", null);
                }
            }

            /**
             * Group index.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/access/groups", null);
            }

            /**
             * Create new group.
             *
             * @param groupid
             * @param comment
             */
            public void createGroup(String groupid, String comment) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("groupid", groupid);
                parameters.put("comment", comment);
                _client.post("/access/groups", parameters);
            }

            /**
             * Create new group.
             *
             * @param groupid
             */
            public void createGroup(String groupid) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("groupid", groupid);
                _client.post("/access/groups", parameters);
            }
        }

        public class PVERoles extends Base {

            protected PVERoles(Client client) {
                _client = client;
            }

            public PVEItemRoleid get(Object roleid) {
                return new PVEItemRoleid(_client, roleid);
            }

            public class PVEItemRoleid extends Base {

                private Object _roleid;

                protected PVEItemRoleid(Client client, Object roleid) {
                    _client = client;
                    _roleid = roleid;
                }

                /**
                 * Delete role.
                 */
                public void deleteRole() throws JSONException {
                    _client.delete("/access/roles/" + _roleid + "", null);
                }

                /**
                 * Get role configuration.
                 */
                public JSONObject readRole() throws JSONException {
                    return _client.get("/access/roles/" + _roleid + "", null);
                }

                /**
                 * Create new role.
                 *
                 * @param privs
                 * @param append
                 */
                public void updateRole(String privs, Boolean append) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("privs", privs);
                    parameters.put("append", append);
                    _client.put("/access/roles/" + _roleid + "", parameters);
                }

                /**
                 * Create new role.
                 *
                 * @param privs
                 */
                public void updateRole(String privs) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("privs", privs);
                    _client.put("/access/roles/" + _roleid + "", parameters);
                }
            }

            /**
             * Role index.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/access/roles", null);
            }

            /**
             * Create new role.
             *
             * @param roleid
             * @param privs
             */
            public void createRole(String roleid, String privs) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("roleid", roleid);
                parameters.put("privs", privs);
                _client.post("/access/roles", parameters);
            }

            /**
             * Create new role.
             *
             * @param roleid
             */
            public void createRole(String roleid) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("roleid", roleid);
                _client.post("/access/roles", parameters);
            }
        }

        public class PVEAcl extends Base {

            protected PVEAcl(Client client) {
                _client = client;
            }

            /**
             * Get Access Control List (ACLs).
             */
            public JSONObject readAcl() throws JSONException {
                return _client.get("/access/acl", null);
            }

            /**
             * Update Access Control List (add or remove permissions).
             *
             * @param path Access control path
             * @param roles List of roles.
             * @param delete Remove permissions (instead of adding it).
             * @param groups List of groups.
             * @param propagate Allow to propagate (inherit) permissions.
             * @param users List of users.
             */
            public void updateAcl(String path, String roles, Boolean delete, String groups, Boolean propagate, String users) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("path", path);
                parameters.put("roles", roles);
                parameters.put("delete", delete);
                parameters.put("groups", groups);
                parameters.put("propagate", propagate);
                parameters.put("users", users);
                _client.put("/access/acl", parameters);
            }

            /**
             * Update Access Control List (add or remove permissions).
             *
             * @param path Access control path
             * @param roles List of roles.
             */
            public void updateAcl(String path, String roles) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("path", path);
                parameters.put("roles", roles);
                _client.put("/access/acl", parameters);
            }
        }

        public class PVEDomains extends Base {

            protected PVEDomains(Client client) {
                _client = client;
            }

            public PVEItemRealm get(Object realm) {
                return new PVEItemRealm(_client, realm);
            }

            public class PVEItemRealm extends Base {

                private Object _realm;

                protected PVEItemRealm(Client client, Object realm) {
                    _client = client;
                    _realm = realm;
                }

                /**
                 * Delete an authentication server.
                 */
                public void delete() throws JSONException {
                    _client.delete("/access/domains/" + _realm + "", null);
                }

                /**
                 * Get auth server configuration.
                 */
                public JSONObject read() throws JSONException {
                    return _client.get("/access/domains/" + _realm + "", null);
                }

                /**
                 * Update authentication server settings.
                 *
                 * @param base_dn LDAP base domain name
                 * @param bind_dn LDAP bind domain name
                 * @param comment Description.
                 * @param default_ Use this as default realm
                 * @param delete A list of settings you want to delete.
                 * @param digest Prevent changes if current configuration file
                 * has different SHA1 digest. This can be used to prevent
                 * concurrent modifications.
                 * @param domain AD domain name
                 * @param port Server port.
                 * @param secure Use secure LDAPS protocol.
                 * @param server1 Server IP address (or DNS name)
                 * @param server2 Fallback Server IP address (or DNS name)
                 * @param tfa Use Two-factor authentication.
                 * @param user_attr LDAP user attribute name
                 */
                public void update(String base_dn, String bind_dn, String comment, Boolean default_, String delete, String digest, String domain, Integer port, Boolean secure, String server1, String server2, String tfa, String user_attr) throws JSONException {
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put("base_dn", base_dn);
                    parameters.put("bind_dn", bind_dn);
                    parameters.put("comment", comment);
                    parameters.put("default", default_);
                    parameters.put("delete", delete);
                    parameters.put("digest", digest);
                    parameters.put("domain", domain);
                    parameters.put("port", port);
                    parameters.put("secure", secure);
                    parameters.put("server1", server1);
                    parameters.put("server2", server2);
                    parameters.put("tfa", tfa);
                    parameters.put("user_attr", user_attr);
                    _client.put("/access/domains/" + _realm + "", parameters);
                }

                /**
                 * Update authentication server settings.
                 */
                public void update() throws JSONException {
                    _client.put("/access/domains/" + _realm + "", null);
                }
            }

            /**
             * Authentication domain index.
             */
            public JSONObject index() throws JSONException {
                return _client.get("/access/domains", null);
            }

            /**
             * Add an authentication server.
             *
             * @param realm Authentication domain ID
             * @param type Realm type. Enum: ad,ldap,pam,pve
             * @param base_dn LDAP base domain name
             * @param bind_dn LDAP bind domain name
             * @param comment Description.
             * @param default_ Use this as default realm
             * @param domain AD domain name
             * @param port Server port.
             * @param secure Use secure LDAPS protocol.
             * @param server1 Server IP address (or DNS name)
             * @param server2 Fallback Server IP address (or DNS name)
             * @param tfa Use Two-factor authentication.
             * @param user_attr LDAP user attribute name
             */
            public void create(String realm, String type, String base_dn, String bind_dn, String comment, Boolean default_, String domain, Integer port, Boolean secure, String server1, String server2, String tfa, String user_attr) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("realm", realm);
                parameters.put("type", type);
                parameters.put("base_dn", base_dn);
                parameters.put("bind_dn", bind_dn);
                parameters.put("comment", comment);
                parameters.put("default", default_);
                parameters.put("domain", domain);
                parameters.put("port", port);
                parameters.put("secure", secure);
                parameters.put("server1", server1);
                parameters.put("server2", server2);
                parameters.put("tfa", tfa);
                parameters.put("user_attr", user_attr);
                _client.post("/access/domains", parameters);
            }

            /**
             * Add an authentication server.
             *
             * @param realm Authentication domain ID
             * @param type Realm type. Enum: ad,ldap,pam,pve
             */
            public void create(String realm, String type) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("realm", realm);
                parameters.put("type", type);
                _client.post("/access/domains", parameters);
            }
        }

        public class PVETicket extends Base {

            protected PVETicket(Client client) {
                _client = client;
            }

            /**
             * Dummy. Useful for formaters which want to priovde a login page.
             */
            public void getTicket() throws JSONException {
                _client.get("/access/ticket", null);
            }

            /**
             * Create or verify authentication ticket.
             *
             * @param password The secret password. This can also be a valid
             * ticket.
             * @param username User name
             * @param otp One-time password for Two-factor authentication.
             * @param path Verify ticket, and check if user have access 'privs'
             * on 'path'
             * @param privs Verify ticket, and check if user have access 'privs'
             * on 'path'
             * @param realm You can optionally pass the realm using this
             * parameter. Normally the realm is simply added to the username
             * &amp;lt;username&amp;gt;@&amp;lt;relam&amp;gt;.
             */
            public JSONObject createTicket(String password, String username, String otp, String path, String privs, String realm) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("password", password);
                parameters.put("username", username);
                parameters.put("otp", otp);
                parameters.put("path", path);
                parameters.put("privs", privs);
                parameters.put("realm", realm);
                return _client.post("/access/ticket", parameters);
            }

            /**
             * Create or verify authentication ticket.
             *
             * @param password The secret password. This can also be a valid
             * ticket.
             * @param username User name
             */
            public JSONObject createTicket(String password, String username) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("password", password);
                parameters.put("username", username);
                return _client.post("/access/ticket", parameters);
            }
        }

        public class PVEPassword extends Base {

            protected PVEPassword(Client client) {
                _client = client;
            }

            /**
             * Change user password.
             *
             * @param password The new password.
             * @param userid User ID
             */
            public void changePasssword(String password, String userid) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("password", password);
                parameters.put("userid", userid);
                _client.put("/access/password", parameters);
            }
        }

        /**
         * Directory index.
         */
        public JSONObject index() throws JSONException {
            return _client.get("/access", null);
        }
    }

    public class PVEPools extends Base {

        protected PVEPools(Client client) {
            _client = client;
        }

        public PVEItemPoolid get(Object poolid) {
            return new PVEItemPoolid(_client, poolid);
        }

        public class PVEItemPoolid extends Base {

            private Object _poolid;

            protected PVEItemPoolid(Client client, Object poolid) {
                _client = client;
                _poolid = poolid;
            }

            /**
             * Delete pool.
             */
            public void deletePool() throws JSONException {
                _client.delete("/pools/" + _poolid + "", null);
            }

            /**
             * Get pool configuration.
             */
            public JSONObject readPool() throws JSONException {
                return _client.get("/pools/" + _poolid + "", null);
            }

            /**
             * Update pool data.
             *
             * @param comment
             * @param delete Remove vms/storage (instead of adding it).
             * @param storage List of storage IDs.
             * @param vms List of virtual machines.
             */
            public void updatePool(String comment, Boolean delete, String storage, String vms) throws JSONException {
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put("comment", comment);
                parameters.put("delete", delete);
                parameters.put("storage", storage);
                parameters.put("vms", vms);
                _client.put("/pools/" + _poolid + "", parameters);
            }

            /**
             * Update pool data.
             */
            public void updatePool() throws JSONException {
                _client.put("/pools/" + _poolid + "", null);
            }
        }

        /**
         * Pool index.
         */
        public JSONObject index() throws JSONException {
            return _client.get("/pools", null);
        }

        /**
         * Create new pool.
         *
         * @param poolid
         * @param comment
         */
        public void createPool(String poolid, String comment) throws JSONException {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("poolid", poolid);
            parameters.put("comment", comment);
            _client.post("/pools", parameters);
        }

        /**
         * Create new pool.
         *
         * @param poolid
         */
        public void createPool(String poolid) throws JSONException {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("poolid", poolid);
            _client.post("/pools", parameters);
        }
    }

    public class PVEVersion extends Base {

        protected PVEVersion(Client client) {
            _client = client;
        }

        /**
         * API version details. The result also includes the global datacenter
         * confguration.
         */
        public JSONObject version() throws JSONException {
            return _client.get("/version", null);
        }
    }
}
