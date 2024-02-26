package burp;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JFileChooser;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import java.io.File;

import com.myjeeva.digitalocean.exception.DigitalOceanException;
import com.myjeeva.digitalocean.exception.RequestUnsuccessfulException;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JTextPane;
import javax.swing.filechooser.FileNameExtensionFilter;

public class DigitalOceanProxyTab extends JPanel {
    private BurpExtender burp;
	private JPasswordField txtDigitalOceanApiKey; // api key
    private JTextField txtOvpnFileLocation; // ovpn file
    // ovpn username
    private JLabel lblOvpnUsername;
    private JTextField txtOvpnUsername;
    // ovpn password
    private JLabel lblOvpnPassword;
    private JPasswordField txtOvpnPassword;
    protected JTextPane textPane;
    // status of the proxy: 0 = not deployed, 1 = deployed and waiting for network, 2 = deployed and ready
    private int STATUS = 0;
    
    public DigitalOceanProxyTab(BurpExtender burp) {
		
		this.burp = burp;
		
		JLabel lblApiKey = new JLabel("DigitalOcean API key");
        JButton btnDestroy = new JButton("Destroy");
        this.textPane = new JTextPane();

        JLabel lblOvpnFile = new JLabel("OpenVPN config file");
        JLabel lblOvpnUsername = new JLabel("username");
        JLabel lblOvpnPassword = new JLabel("password");
        JFileChooser ovpnFileChooser = new JFileChooser();
        JButton btnOvpnFileChooser = new JButton("Browse");
        ovpnFileChooser.setFileFilter(new FileNameExtensionFilter("OpenVPN files", "ovpn"));
        ovpnFileChooser.setAcceptAllFileFilterUsed(false);
        ovpnFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        ovpnFileChooser.setMultiSelectionEnabled(false);
        ovpnFileChooser.setControlButtonsAreShown(false);
        ovpnFileChooser.setApproveButtonText("Select");
        ovpnFileChooser.setDialogTitle("Select OpenVPN config file");
        // ...

                ovpnFileChooser.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        if(e.getActionCommand().equals(JFileChooser.APPROVE_SELECTION)) {
                            File file = ovpnFileChooser.getSelectedFile();
                            txtOvpnFileLocation.setText(file.getAbsolutePath());
                            burp.setOvpnFileLocation(file.getAbsolutePath());
                        }
                    }
                });

                btnOvpnFileChooser.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        ovpnFileChooser.showOpenDialog(null);
                    }
                });

				
		JButton btnDeploy = new JButton("Deploy");
		btnDeploy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				burp.setApiKey(txtDigitalOceanApiKey.getText());
                burp.setOvpnCredentials(txtOvpnUsername.getText(), txtOvpnPassword.getText());
				
				try {
                    // First get list of existing droplet in account that weren't deleted yet
                    int nbExisting = burp.loadExistingProxyDroplets();
                    if(nbExisting > 0) {
                        textPane.setText("WARNING: there are still "+nbExisting+" proxies deployed - they will be removed when hitting the Destroy button.");
                    }


                    btnDeploy.setEnabled(false);
                    textPane.setText(textPane.getText() + "\nDeploying openvpn proxy to DigitalOcean...");
                    burp.deployNewDODroplet("burp-openvpn","nyc1","s-1vcpu-1gb");
                    textPane.setText(textPane.getText() + "\nProxy droplet is being deployed, waiting to come online...");
                    STATUS = 1;
                    Thread thread = new Thread(() -> {
                        // as long as status is "new", wait 60 seconds and check again
                        try {
                            while(burp.getDropletStatus().equals("new")) {
                                textPane.setText(textPane.getText() + "\nProxy droplet is not ready yet, waiting 60 seconds...");
                                try {
                                    Thread.sleep(60000);
                                } catch (InterruptedException e2) {
                                    e2.printStackTrace();
                                }
                            }
                        } catch (DigitalOceanException | RequestUnsuccessfulException e1) {
                            e1.printStackTrace();
                        }
                        finishedWaiting();
                        btnDestroy.setEnabled(true);
                    });
                    thread.start();
                } catch (DigitalOceanException | RequestUnsuccessfulException e1) {
                    burp.stdout.println("Error deploying droplet: " + e1.getMessage());
                    e1.printStackTrace();
                }
			}
		});
		
		txtDigitalOceanApiKey = new JPasswordField(burp.api_key);
		txtDigitalOceanApiKey.setColumns(10);
        txtOvpnFileLocation = new JTextField(burp.ovpn_file);
        txtOvpnFileLocation.setColumns(10);
        txtOvpnFileLocation.setEnabled(false);
        txtOvpnUsername = new JTextField(burp.ovpn_username);
        txtOvpnUsername.setColumns(10);
        txtOvpnPassword = new JPasswordField(burp.ovpn_password);
        txtOvpnPassword.setColumns(10);
		
		btnDestroy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
                // you can't destroy what is never built
                if(STATUS == 0) return;
                try {
                    btnDestroy.setEnabled(false);
                    textPane.setText(textPane.getText() +"\nDestroying OpenVPN proxy...");
                    burp.destroyAllDroplets();
                    textPane.setText(textPane.getText() +"\nResetting Burp socks proxy config...");
                    burp.clearProxyConfiguration();
                    textPane.setText(textPane.getText() +"\nProxy destroyed.");
                    STATUS = 0;
                    btnDeploy.setEnabled(true);
                } catch (Exception e1) {
                    burp.stdout.println("Error destroying proxy: " + e1.getMessage());
                    e1.printStackTrace();
                }
				
			}
		});
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(45)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(textPane, GroupLayout.PREFERRED_SIZE, 615, GroupLayout.PREFERRED_SIZE)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(lblApiKey)
							.addGap(43)
							.addComponent(txtDigitalOceanApiKey, GroupLayout.PREFERRED_SIZE, 318, GroupLayout.PREFERRED_SIZE)
							.addGap(3)
                            .addComponent(btnDeploy)
                            .addGap(3)
							.addComponent(btnDestroy))
                        .addGap(45)
                        .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                            .addGroup(groupLayout.createSequentialGroup()
                                .addComponent(lblOvpnFile)
                                .addGap(43)
                                .addComponent(txtOvpnFileLocation, GroupLayout.PREFERRED_SIZE, 318, GroupLayout.PREFERRED_SIZE)
                                .addComponent(btnOvpnFileChooser)
                            ))
                        .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                            .addGroup(groupLayout.createSequentialGroup()
                                .addComponent(lblOvpnUsername)
                                .addGap(43)
                                .addComponent(txtOvpnUsername, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                            ))
                        .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                            .addGroup(groupLayout.createSequentialGroup()
                                .addComponent(lblOvpnPassword)
                                .addGap(43)
                                .addComponent(txtOvpnPassword, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                            ))
                        )
					.addContainerGap(20, Short.MAX_VALUE))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(40)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(4)
							.addComponent(lblApiKey))
						.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
							.addComponent(txtDigitalOceanApiKey, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDeploy)
							.addComponent(btnDestroy)))
                    .addGap(18)
                    .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                        .addComponent(lblOvpnFile)
                        .addComponent(txtOvpnFileLocation, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnOvpnFileChooser))
                    // ovpn username
                    .addGap(18)
                    .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                        .addComponent(lblOvpnUsername)
                        .addComponent(txtOvpnUsername, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    // ovpn password
                    .addGap(18)
                    .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                        .addComponent(lblOvpnPassword)
                        .addComponent(txtOvpnPassword, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGap(18)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(textPane, GroupLayout.DEFAULT_SIZE, 49, Short.MAX_VALUE)
					.addGap(38))
		);
		setLayout(groupLayout);

	}

    protected void finishedWaiting() {
        // don't execute this if the proxy is destroyed in the meantime
        if(STATUS == 0)
            return;
        
        textPane.setText(textPane.getText() + "\nProxy droplet is ready, configuring proxy...");
        try {
            String ip = burp.getCurrentDropletIP();
            textPane.setText(textPane.getText() + "\nProxy IP: " + ip);
        } catch (DigitalOceanException | RequestUnsuccessfulException e) {
            e.printStackTrace();
        }        
        burp.configureSocksProxy();
        textPane.setText(textPane.getText() +"\nBurp SOCKS proxy settings configured.");
        textPane.setText(textPane.getText() +"\nProxy is ready to use. Allow some time for the Docker images to start.");
        textPane.setText(textPane.getText() +"\nOpening repeater tab...");
        burp.openIfconfigRepeaterTab();
        STATUS = 2;
    }
}
