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

import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.OneToOne;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;dynamic-insertion&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class RestrictContentTypeRule extends Rule {
	
	private static final long serialVersionUID = 1L;

	@Transient
	private Pattern allow;
	
	@Transient
	private Pattern deny;
	
	@OneToOne
	private UrlPath allow1;
	
	@OneToOne
	private UrlPath deny1;
	
	public RestrictContentTypeRule(){
		allow1 = new UrlPath();
		deny1 = new UrlPath();
	}

	public RestrictContentTypeRule(String id, Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		/* can't check content type if it's not available */
		if ( request.getContentType() == null ) {
			return new DoNothingAction();
		}

		if ( allow != null ) {
			if ( allow.matcher(request.getContentType()).matches() ) {
				return new DoNothingAction();
			}
			log(request, "Disallowed content type based on allow pattern '" + allow.pattern() + "' found on URI '" + request.getRequestURI() + "' (value was '" + request.getContentType() +"')");
		} else if ( deny != null ) {
			if ( ! deny.matcher(request.getContentType()).matches() ) {
				return new DoNothingAction();
			}
			log(request, "Disallowed content type based on deny pattern '" + deny.pattern() + "' found on URI '" + request.getRequestURI() + "' (value was '" + request.getContentType() + ")'");
		}


		return new DefaultAction();

	}

	public UrlPath getAllow1() {
		return allow1;
	}

	public void setAllow1(UrlPath allow1) {
		this.allow1 = allow1;
	}

	public UrlPath getDeny1() {
		return deny1;
	}

	public void setDeny1(UrlPath deny1) {
		this.deny1 = deny1;
	}

}
