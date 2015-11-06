package org.owasp.esapi.waf.rules;

import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Transient;

@Entity
public class UrlPath extends PatternEntity {
	
	private boolean isRegex;
	
	public UrlPath (){
		this.setRegex("/");
		this.isRegex = true;
	}
	
	public UrlPath(Pattern pattern){
		super(pattern);
		this.isRegex = true;
	}
	
	public UrlPath(String url){
		this.pattern = null;
		this.setUrl(url);
		this.isRegex = false;
	}
	
	public boolean matches(String uri){
		if (isRegex){			
			return super.matches(uri);				
		} else {
			return this.getUrl().equals(uri);
		}
	}
		
		
	public UrlPath (String path, boolean regex){
		this.setUrl(path);
		this.isRegex = regex;
	}

	public String getUrl() {
		return super.getRegex();
	}

	public void setUrl(String url) {
		super.setRegex(url);
	}

	public boolean isRegex() {
		return isRegex;
	}

	public void setIsRegex(boolean isRegex) {
		this.isRegex = isRegex;
	}
}
