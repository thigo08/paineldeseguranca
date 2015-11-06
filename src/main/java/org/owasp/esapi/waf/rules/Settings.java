package org.owasp.esapi.waf.rules;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToOne;

@Entity
public class Settings{
	
	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE)
	private Long id;
	
	private String mode;
	
	private String sessionCookieName;
	
	@OneToOne
	private UrlPath defaultRedirectPage;
	
	private String blockStatus;
	
	public Settings(){
		defaultRedirectPage = new UrlPath();
	}
	
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getMode() {
		return mode;
	}

	public void setMode(String mode) {
		this.mode = mode;
	}

	public String getSessionCookieName() {
		return sessionCookieName;
	}

	public void setSessionCookieName(String sessionCookieName) {
		this.sessionCookieName = sessionCookieName;
	}

	public UrlPath getDefaultRedirectPage() {
		return defaultRedirectPage;
	}

	public void setDefaultRedirectPage(UrlPath defaultRedirectPage) {
		this.defaultRedirectPage = defaultRedirectPage;
	}

	public String getBlockStatus() {
		return blockStatus;
	}

	public void setBlockStatus(String blockStatus) {
		this.blockStatus = blockStatus;
	}
	
}
