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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.actions.RedirectAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;enforce-https&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class EnforceHTTPSRule extends Rule {

	private static final long serialVersionUID = 1L;
	
	@Transient
	private Pattern path;
	
	@Transient
	private List<Object> exceptions;
	
	private String action;
	
	@OneToOne
	private UrlPath path1;
	
	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval=true)
	private List<UrlPath> exceptions1;

	/*
	 * action = [ redirect | block ] [=default (redirect will redirect to error page]
	 */

	public EnforceHTTPSRule(){
		path1 = new UrlPath();
	}
	
	public EnforceHTTPSRule(String id, Pattern path, List<Object> exceptions, String action) {
		this.path = path;
		this.exceptions = exceptions;
		this.action = action;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		if ( ! request.isSecure() ) {

			if ( path.matcher(request.getRequestURI()).matches() ) {

				Iterator<Object> it = exceptions.iterator();

				while(it.hasNext()){

					Object o = it.next();

					if ( o instanceof String ) {
						if ( ((String)o).equalsIgnoreCase(request.getRequestURI()) ) {
							return new DoNothingAction();
						}
					} else if ( o instanceof Pattern ) {
						if ( ((Pattern)o).matcher(request.getRequestURI()).matches() ) {
							return new DoNothingAction();
						}
					}

				}

				log(request,"Insecure request to resource detected in URL: '" + request.getRequestURL() + "'");

				if ( "redirect".equals(action) ) {
					RedirectAction ra = new RedirectAction();
					ra.setRedirectURL(request.getRequestURL().toString().replaceFirst("http", "https"));
					return ra;
				}

				return new DefaultAction();

			}
		}

		return new DoNothingAction();

	}

	public String getAction() {
		return action;
	}

	public void setAction(String action) {
		this.action = action;
	}

	public UrlPath getPath1() {
		return path1;
	}

	public void setPath1(UrlPath path1) {
		this.path1 = path1;
	}

	public List<UrlPath> getExceptions1() {
		if (exceptions1 == null)
			exceptions1 = new ArrayList<UrlPath>();
		return exceptions1;
	}

	public void setExceptions1(List<UrlPath> exceptions1) {
		this.exceptions1 = exceptions1;
	}
	
}
