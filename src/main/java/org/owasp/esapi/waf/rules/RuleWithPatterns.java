package org.owasp.esapi.waf.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;

@Entity
public abstract class RuleWithPatterns extends RuleWithUrlPath {

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval=true)
	@JoinColumn(name = "fk_id_rule")
	private List<PatternEntity> patternList;
	
	public RuleWithPatterns (){
		super();
	}
	
	public void fillListOfPatternEntity (List<Pattern> list){
		for (Pattern pattern : list){
			getPatternList().add(new PatternEntity(pattern));
		}
	}
	
	public List<PatternEntity> getPatternList() {
		if (patternList == null)
			patternList = new ArrayList<PatternEntity>();
		return patternList;
	}

	public void setPatternList(List<PatternEntity> list) {
		this.patternList = list;
	}
	
	
}
