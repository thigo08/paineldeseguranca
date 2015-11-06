package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.UrlPath;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class UrlPathDAO extends JPACrud<UrlPath, Long> {

	private static final long serialVersionUID = 1L;

}
