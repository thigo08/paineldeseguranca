package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.DetectOutboundContentRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class DetectOutboundContentRuleDAO extends JPACrud<DetectOutboundContentRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}