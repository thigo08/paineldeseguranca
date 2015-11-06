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
 * This is the Rule subclass executed for &lt;restrict-method&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class HTTPMethodRule extends Rule {
	
	private static final long serialVersionUID = 1L;

	@Transient
	private Pattern allowedMethods;
	
	@Transient
	private Pattern deniedMethods;
	
	@Transient
	private Pattern path;
	
	@OneToOne
	private UrlPath allowedMethods1;
	
	@OneToOne
	private UrlPath deniedMethods1;
	
	@OneToOne
	private UrlPath path1;
	
	public HTTPMethodRule (){
		allowedMethods1 = new UrlPath();
		deniedMethods1 = new UrlPath();
		path1 = new UrlPath();
	}

	public HTTPMethodRule(String id, Pattern allowedMethods, Pattern deniedMethods, Pattern path) {
		this.allowedMethods = allowedMethods;
		this.deniedMethods = deniedMethods;
		this.path = path;
		//setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		/*
		 * If no path is specified, apply rule globally.
		 */
		String uri = request.getRequestURI();
		String method = request.getMethod();

		if ( path == null || path.matcher(uri).matches() ) {
			/*
			 *	Order allow, deny.
			 */

			if ( allowedMethods != null && allowedMethods.matcher(method).matches() ) {
				return new DoNothingAction();
			} else if ( allowedMethods != null ) {
				log(request,"Disallowed HTTP method '" + request.getMethod() + "' found for URL: " + request.getRequestURL());
				return new DefaultAction();
			}

			if ( deniedMethods != null && deniedMethods.matcher(method).matches() ) {
				log(request,"Disallowed HTTP method '" + request.getMethod() + "' found for URL: " + request.getRequestURL());
				return new DefaultAction();
			}

		}

		return new DoNothingAction();
	}

	public UrlPath getAllowedMethods1() {
		return allowedMethods1;
	}

	public void setAllowedMethods1(UrlPath allowedMethods1) {
		this.allowedMethods1 = allowedMethods1;
	}

	public UrlPath getDeniedMethods1() {
		return deniedMethods1;
	}

	public void setDeniedMethods1(UrlPath deniedMethods1) {
		this.deniedMethods1 = deniedMethods1;
	}

	public UrlPath getPath1() {
		return path1;
	}

	public void setPath1(UrlPath path1) {
		this.path1 = path1;
	}
	
}
