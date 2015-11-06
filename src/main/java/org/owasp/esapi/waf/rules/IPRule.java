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
 * This is the Rule subclass executed for &lt;detect-source-ip&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class IPRule extends Rule {
	
	private static final long serialVersionUID = 1L;

	@Transient
	private Pattern allowedIP;
	
	private String exactPath;
	
	@Transient
	private Pattern path;
	
	private boolean useExactPath = false;
	
	private String ipHeader;
	
	@OneToOne
	private UrlPath allowedIP1;
	
	@OneToOne
	private UrlPath path1;
	
	public IPRule(){
		allowedIP1 = new UrlPath();
		path1 = new UrlPath();
	}

	public IPRule(String id, Pattern allowedIP, Pattern path, String ipHeader) {
		this.allowedIP = allowedIP;
		this.path = path;
		this.useExactPath = false;
		this.ipHeader = ipHeader;
		//setId(id);
	}

	public IPRule(String id, Pattern allowedIP, String exactPath) {
		this.path = null;
		this.exactPath = exactPath;
		this.useExactPath = true;
		//setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		String uri = request.getRequestURI();

		if ( (!useExactPath && path.matcher(uri).matches()) ||
			 ( useExactPath && exactPath.equals(uri)) ) {
			
			String sourceIP = request.getRemoteAddr() + "";
			
			if ( ipHeader != null ) {
				sourceIP = request.getHeader(ipHeader);
			}
			
			if ( ! allowedIP.matcher(sourceIP).matches() ) {
				log(request, "IP not allowed to access URI '" + uri + "'");
				return new DefaultAction();
			}
		}

		return new DoNothingAction();
	}

	public String getExactPath() {
		return exactPath;
	}

	public void setExactPath(String exactPath) {
		this.exactPath = exactPath;
	}

	public boolean isUseExactPath() {
		return useExactPath;
	}

	public void setUseExactPath(boolean useExactPath) {
		this.useExactPath = useExactPath;
	}

	public String getIpHeader() {
		return ipHeader;
	}

	public void setIpHeader(String ipHeader) {
		this.ipHeader = ipHeader;
	}

	public UrlPath getAllowedIP1() {
		return allowedIP1;
	}

	public void setAllowedIP1(UrlPath allowedIP1) {
		this.allowedIP1 = allowedIP1;
	}

	public UrlPath getPath1() {
		return path1;
	}

	public void setPath1(UrlPath path1) {
		this.path1 = path1;
	}
	
}
