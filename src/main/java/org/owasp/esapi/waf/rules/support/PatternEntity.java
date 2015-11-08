package org.owasp.esapi.waf.rules.support;

import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Transient;

import org.owasp.esapi.waf.rules.Rule;

@Entity
@Inheritance(strategy=InheritanceType.SINGLE_TABLE)
public class PatternEntity {
	@Id
	@GeneratedValue
	private Long id;
	
	private String regex;
	
	@ManyToOne
	@JoinColumn(name = "fk_id_rule")
	private Rule rule;
	
	@Transient
	protected Pattern pattern;

	public PatternEntity(){
		
	}
	
	public PatternEntity(String regex) {
		this.setRegex(regex);
		this.pattern = Pattern.compile(regex);
	}
	
	public PatternEntity (Pattern pattern) {
		this.setRegex(pattern.pattern());
		this.pattern = pattern;
	}
	
	public Pattern getPattern(){
		if (pattern == null)
			pattern = Pattern.compile(getRegex());
		return pattern;
	}
	
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}
	
	public boolean matches (String param){
		
		return getPattern().matcher(param).matches();
	}

	public String getRegex() {
		return regex;
	}

	public void setRegex(String regex) {
		this.regex = regex;
	}
	
	public Rule getRule() {
		return rule;
	}

	public void setRule(Rule rule) {
		this.rule = rule;
	}
	
	public String pattern(){
		return getPattern().pattern();
	}
}
