package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

public class ProjectSettings implements IHttpRequestResponse {

	private BurpExtender burp;
	private static final String SITEMAP_PREFIX = "BURP_PROJECT_SETTINGS_DO_NOT_DELETE";
	private IHttpService httpService;
	private byte[] requestBytes;
	private HashMap<String, String> settings;
	private byte[] serialized_settings;
	
	public ProjectSettings(BurpExtender burp, String extensionName) {
		this.burp = burp;
		this.httpService = burp.callbacks.getHelpers().buildHttpService(SITEMAP_PREFIX, 65535, true);
		IHttpRequestResponse[] settingsSiteMap = burp.callbacks.getSiteMap(this.httpService.toString()+"/"+extensionName);
		
		try {
			// need to overwrite the request bytes to force Burp to add it to the sitemap as a new item
			this.requestBytes = burp.callbacks.getHelpers().buildHttpRequest(new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), "/"+extensionName));
			if(settingsSiteMap.length > 0) {
				this.serialized_settings = settingsSiteMap[0].getResponse();
			}
		} catch (MalformedURLException e) {
			burp.stdout.println("ProjectSettings: Malformed URL");
		}
	}	
	
	@Override
	public byte[] getRequest() {
		return requestBytes;
	}

	@Override
	public void setRequest(byte[] message) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public byte[] getResponse() {
		if(this.serialized_settings != null) {
			return this.serialized_settings;
		}
		
		return "".getBytes();
	}

	@Override
	public void setResponse(byte[] message) {
		this.serialized_settings = message;
	}

	@Override
	public String getComment() {
		return null;
	}

	@Override
	public void setComment(String comment) {}

	@Override
	public String getHighlight() {
		return null;
	}

	@Override
	public void setHighlight(String color) {}

	@Override
	public IHttpService getHttpService() {
		return this.httpService;
	}

	@Override
	public void setHttpService(IHttpService httpService) {
		this.httpService = httpService;
	}

	/**
	 * Store settings as a key-value map in a special project settings request in the site map
	 * @param string
	 * @param program_name
	 */
	public void saveProjectSetting(String key, String value) {
		if(this.settings == null) {
			this.settings = new HashMap<String, String>();
		}
		this.settings.put(key, value);
	
		// store values as KEY=VALUE;KEY2=VALUE2
		String serialized = "";
		for(String s : this.settings.keySet()) {
			serialized += s+"="+this.settings.get(s)+";";
		}
		this.setResponse(this.burp.callbacks.getHelpers().stringToBytes(serialized));
		burp.callbacks.addToSiteMap(this);
	}

	public String loadProjectSetting(String key) {
		
		// init hashmap from serialized data in request
		if(this.settings == null) {
			
			this.settings = new HashMap<String, String>();
			
			String serialized = this.burp.callbacks.getHelpers().bytesToString(this.getResponse());
			String[] parts = serialized.split(";");
			for(String p: parts) {
				String[] pp = p.split("=");
				if(pp.length == 2) {
					this.settings.put(pp[0], pp[1]);
				}
			}
		}
		
		return this.settings.get(key);
	}

}
