package org.owasp.esapi.waf.rules;

import javax.persistence.Column;
import javax.persistence.Entity;

@Entity
public class Alias extends UrlPath{
	
	@Column(unique=true)
	private String name;
	
	public Alias(){
		
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
}
