package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.Settings;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class SettingsDAO extends JPACrud<Settings, Long> {
	
	private static final long serialVersionUID = 1L;
}
