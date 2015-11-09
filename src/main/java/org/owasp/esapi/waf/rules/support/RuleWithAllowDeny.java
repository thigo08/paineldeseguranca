package org.owasp.esapi.waf.rules.support;

import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.OneToOne;

import org.owasp.esapi.waf.rules.Rule;


@Entity
@Inheritance(strategy=InheritanceType.SINGLE_TABLE)
public abstract class RuleWithAllowDeny extends Rule {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@OneToOne
	private PatternEntity allow;
	
	@OneToOne
	private PatternEntity deny;
	
	public RuleWithAllowDeny(){
		this.allow = new PatternEntity();
		this.deny = new PatternEntity();
	}
	
	public RuleWithAllowDeny(Pattern allow, Pattern deny){
		this.setAllow(new PatternEntity(allow));
		this.setDeny(new PatternEntity(deny));
	}

	public PatternEntity getAllow() {
		return allow;
	}

	public void setAllow(PatternEntity allow) {
		this.allow = allow;
	}

	public PatternEntity getDeny() {
		return deny;
	}

	public void setDeny(PatternEntity deny) {
		this.deny = deny;
	}
}
