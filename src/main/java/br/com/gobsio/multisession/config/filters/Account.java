package br.com.gobsio.multisession.config.filters;

import org.springframework.security.core.Authentication;

public class Account {
	private String username;

	private String logoutUrl;

	private String switchAccountUrl;

    private Authentication authentication;

	public Account(String username, String logoutUrl, String switchAccountUrl) {
		super();
		this.username = username;
		this.logoutUrl = logoutUrl;
		this.switchAccountUrl = switchAccountUrl;
	}

	public String getUsername() {
		return this.username;
	}

	public String getLogoutUrl() {
		return this.logoutUrl;
	}

	public String getSwitchAccountUrl() {
		return this.switchAccountUrl;
	}

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

}