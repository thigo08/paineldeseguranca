package org.owasp.esapi.waf.rules;

import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

@Entity
public abstract class RuleWithUrlPath extends Rule {

	@OneToOne
	@JoinColumn(name = "fk_id_rule") 
	private UrlPath path;
	
	public RuleWithUrlPath(){
		path = new UrlPath();
	}
	
	public RuleWithUrlPath(String url){
		this.path = new UrlPath(url);
	}
	
	public RuleWithUrlPath(Pattern pattern){
		this.path = new UrlPath(pattern);
	}
	
	public UrlPath getPath() {
		return path;
	}

	public void setPath(UrlPath path) {
		this.path = path;
	}

}
