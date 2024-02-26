package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.JDialog;
import javax.swing.JMenu;
import javax.swing.JMenuItem;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import com.myjeeva.digitalocean.*;
import com.myjeeva.digitalocean.impl.DigitalOceanClient;
import com.myjeeva.digitalocean.pojo.*;
import com.myjeeva.digitalocean.exception.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;

public class BurpExtender extends JDialog implements IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab  {

    protected IBurpExtenderCallbacks callbacks;
	protected PrintWriter stdout;
    protected String api_key;
    protected String ovpn_file; // the file location of the last loaded OVPN file
    protected String ovpn_username; // the username to use for the OVPN file
    protected String ovpn_password; // the password to use for the OVPN file
    private String ip;
    private int proxyCount = 0;
    private DigitalOcean apiClient;
    protected ProjectSettings settings;

    // gui elements
	public DigitalOceanProxyTab myPanel;

    // keep a copy of our openvpn droplet
    Droplet droplet = new Droplet();
    // the script to run on the droplet when it is created
    protected String droplet_init_script = "#!/bin/bash\n" +
        "mkdir -p /tmp/openvpn\n" +
        "cat <<EOF > /tmp/openvpn/config.ovpn\n" +
        "PLACEHOLDER_OVPN\n" +
        "EOF\n" +
        "docker run -d --name openvpn -p 1080:1080 --cap-add=NET_ADMIN --device /dev/net/tun -v /tmp/openvpn:/vpn dperson/openvpn-client PLACEHOLDER_AUTH\n" +
        "docker run -d --name socks5 --network container:openvpn -e PROXY_USER=burp -e PROXY_PASSWORD=changeme serjs/go-socks5-proxy\n";
    // the socks password
    private CharSequence password;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("OpenVPN/SOCKS Proxy");
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.callbacks = callbacks;

		// unload resources when this extension is removed;
        stdout.println("Registering extension state listener.");
		callbacks.registerExtensionStateListener(this);

        // load extension-specific settings
        stdout.println("Loading existing settings.");
        this.api_key = callbacks.loadExtensionSetting("digitalocean-api-key");
        // this.ovpn_file = callbacks.loadExtensionSetting("ovpn-file-location");

        // load project-specific settings
        this.settings = new ProjectSettings(this, "digitalocean-openvpn-socks");
        this.ovpn_file = settings.loadProjectSetting("ovpn-file-location");
        this.ovpn_username = settings.loadProjectSetting("ovpn-username");
        this.ovpn_password = settings.loadProjectSetting("ovpn-password");

        // create the tab
        stdout.println("Creating DigitalOcean OVPN Proxy tab.");
        myPanel = new DigitalOceanProxyTab(this);
        callbacks.addSuiteTab(this);

        // register the right-click menu:
		callbacks.registerContextMenuFactory(this);

        stdout.println("OpenVPN/SOCKS extension initialized.");
    
    }

    // use the DigitalOcean API to create a new droplet
    protected void deployNewDODroplet(String droplet_name, String region, String size) throws DigitalOceanException, RequestUnsuccessfulException {
        proxyCount++;
        apiClient = new DigitalOceanClient(this.api_key);
        Droplet newDroplet = new Droplet();
        newDroplet.setName(droplet_name);
        newDroplet.setSize(size);
        newDroplet.setRegion(new Region(region));
        newDroplet.setImage(new Image("docker-20-04")); // use docker so we can run the necessary containers
        newDroplet.setTags(Arrays.asList("burp-openvpn")); // set a tag so they get removed when hitting "destroy"

        // add your public ssh key to the droplet
        //List<Key> keys = new ArrayList<Key>();
        //keys.add(new Key(123));
        //newDroplet.setKeys(keys);

        // generate a new password if we don't have one yet (first droplet)
        
        if(this.password == null) {
            this.password = randomPassword(16); 
            stdout.println("Generated random password for socks proxy: " + this.password);
        }

                try {
                    // set the init script to run on the droplet
                    // copy the ovpn configuration to the droplet and start the openvpn and socks5 containers
                    String ovpn = new String(Files.readAllBytes(Paths.get(this.ovpn_file)));
                    String auth = "";
                    if(this.ovpn_username != null && !this.ovpn_username.isEmpty()) {
                        // escape all bash special characters (forward slashes, doller signs, backticks, backslashes, single quotes, double quotes, exclamation marks, and asterisks)
                        auth = "-a '"+ this.ovpn_username + ";"+this.ovpn_password.replaceAll("([/\\$`'\"!\\*])", "\\\\$1")+"'";
                    }
                    newDroplet.setUserData(droplet_init_script.replace("changeme", this.password)
                        .replace("PLACEHOLDER_OVPN", ovpn)
                        .replace("PLACEHOLDER_AUTH", auth));
                
                    // create a new droplet
                    stdout.println("Creating new droplet: " + newDroplet.getName());
                } catch (IOException e) {
                    e.printStackTrace();
                    stdout.println("Error reading ovpn file: " + e.getMessage());
                }
                this.droplet = apiClient.createDroplet(newDroplet);
    }

    // get a list of droplets named burp-openvpn* that already exist on the account
    // note that these cannot be used because the proxy password is randomized;
    // return the number of existing proxy droplets found.
    protected int loadExistingProxyDroplets() {
        apiClient = new DigitalOceanClient(this.api_key);
        Droplets existing_droplets;
        try {
            existing_droplets = apiClient.getAvailableDropletsByTagName("burp-openvpn", 1, 100);
            return existing_droplets.getDroplets().size();
        } catch (DigitalOceanException | RequestUnsuccessfulException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return -1;
    }

    // generate a random password for the socks proxy
    private CharSequence randomPassword(int i) {   
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
        StringBuilder sb = new StringBuilder(i);
        for (int j = 0; j < i; j++) {
            int index = (int) (AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString.charAt(index));
        }
        return sb;
    }


    // destroy one droplet by its id
    protected void destroyDODroplet(int droplet_id) throws DigitalOceanException, RequestUnsuccessfulException {
        DigitalOcean apiClient = new DigitalOceanClient(this.api_key);
        stdout.println("Destroying droplets");
        apiClient.deleteDroplet(droplet_id);
        // reset the IP so it gets refreshed for next droplet
        this.ip = null;
    }

    // destroy all droplets
    protected void destroyAllDroplets() throws DigitalOceanException, RequestUnsuccessfulException {
        DigitalOcean apiClient = new DigitalOceanClient(this.api_key);
        apiClient.deleteDropletByTagName("burp-openvpn");
        stdout.println("Destroying droplet: " + this.droplet.getName());
        apiClient.deleteDroplet(this.droplet.getId());
        // reset the IP so it gets refreshed for next droplet
        this.ip = null;
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Destroying all droplets...");
        try {
            this.destroyAllDroplets();
        } catch(Exception e) {
            stdout.println("ERROR - Failed to destroy droplets");
            stdout.println(e.getMessage());
        }
        
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menu = new ArrayList<JMenuItem>();
		
		JMenuItem enableProxy = new JMenuItem("Tunnel through OpenVPN proxy");
		JMenuItem disableProxy = new JMenuItem("Stop tunnelling through OpenVPN proxy");
		
		IHttpRequestResponse[] selected = invocation.getSelectedMessages();
		
		enableProxy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				configureSocksProxy();
			}
		});
		
		disableProxy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				clearProxyConfiguration();
			}
		});
        
		menu.add(enableProxy);
        menu.add(disableProxy);
		
		return menu;
    }

    @Override
    public String getTabCaption() {
        return "OpenVPN/SOCKS";
    }

    @Override
    public Component getUiComponent() {
        return myPanel;
    }

    protected void configureSocksProxy() {
        String ip = "";
        try {
            ip = this.getCurrentDropletIP();
        } catch (DigitalOceanException | RequestUnsuccessfulException e) {
            stdout.println("ERROR - Failed to get droplet IP address.");
            e.printStackTrace();
        }
        myPanel.textPane.setText(myPanel.textPane.getText() + "\nChanging Burp SOCKS proxy settings...");
        callbacks.loadConfigFromJson("{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false,\"host\":\"ip_address\",\"password\":\"changeme\",\"port\":1080,\"use_proxy\":true,\"use_user_options\":false,\"username\":\"burp\"}}}}"
        .replace("ip_address",ip)
        .replace("changeme",this.password));
    }

    public void clearProxyConfiguration() {
        callbacks.loadConfigFromJson("{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false,\"host\":\"0.0.0.0\",\"password\":\"changeme\",\"port\":1080,\"use_proxy\":false,\"use_user_options\":false,\"username\":\"burp\"}}}}");
    }

    public void setApiKey(String api_key) {
        this.api_key = api_key;
        callbacks.saveExtensionSetting("digitalocean-api-key", api_key);
    }

    public void setOvpnFileLocation(String ovpn_file) {
        this.ovpn_file = ovpn_file;
        settings.saveProjectSetting("ovpn-file-location", ovpn_file);
    }

    public void setOvpnCredentials(String ovpn_username, String ovpn_password) {
        if(ovpn_username == null) {
            ovpn_username = "";
        }
        if(ovpn_password == null) {
            ovpn_password = "";
        }
        this.ovpn_username = ovpn_username;
        this.ovpn_password = ovpn_password;
        settings.saveProjectSetting("ovpn-username", ovpn_username);
        settings.saveProjectSetting("ovpn-password", ovpn_password);
    }

    public void refreshDroplet() throws DigitalOceanException, RequestUnsuccessfulException {
        stdout.println("Refreshing droplet information...");
        this.droplet = apiClient.getDropletInfo(this.droplet.getId());
    }

   public String getCurrentDropletIP() throws DigitalOceanException, RequestUnsuccessfulException {
        //if(this.ip != null && !this.ip.isEmpty()) {
        //    return this.ip;
        //}
        this.refreshDroplet();
        stdout.println("Getting droplet IP address: " + this.droplet.getName());
        this.ip = this.droplet.getNetworks().getVersion4Networks().get(0).getIpAddress();
        return this.ip;
    }

    public String getDropletStatus() throws DigitalOceanException, RequestUnsuccessfulException {
        this.refreshDroplet();
        return this.droplet.getStatus().toString();
    }

    protected void openIfconfigRepeaterTab() {
        stdout.println("Opening ifconfig.co repeater tab...");
        String request = "GET / HTTP/1.1\nHost: ifconfig.co\nUser-Agent: curl\n\n";
        callbacks.sendToRepeater("ifconfig.co", 443, true, callbacks.getHelpers().stringToBytes(request), "IP check");
    }

}