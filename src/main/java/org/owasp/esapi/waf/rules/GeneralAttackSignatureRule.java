/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf.rules;

import java.util.Enumeration;
import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.OneToOne;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;general-attack-signature&gt; rules, which 
 * are not currently implemented.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class GeneralAttackSignatureRule extends Rule {
	
	private static final long serialVersionUID = 1L;

	@Transient
	private Pattern signature;
	
	@OneToOne
	private UrlPath signature1;
	
	public GeneralAttackSignatureRule(){
		signature1 = new UrlPath();
	}

	public GeneralAttackSignatureRule(String id, Pattern signature) {
		this.signature = signature;
		//ssetId(id);
	}

	public Action check(HttpServletRequest req,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		InterceptingHTTPServletRequest request = (InterceptingHTTPServletRequest)req;
		Enumeration e = request.getParameterNames();

		while(e.hasMoreElements()) {
			String param = (String)e.nextElement();
			if ( signature.matcher(request.getDictionaryParameter(param)).matches() ) {
				log(request,"General attack signature detected in parameter '" + param + "' value '" + request.getDictionaryParameter(param) + "'");
				return new DefaultAction();
			}
		}

		return new DoNothingAction();
	}

	public UrlPath getSignature1() {
		return signature1;
	}

	public void setSignature1(UrlPath signature1) {
		this.signature1 = signature1;
	}
	
}
