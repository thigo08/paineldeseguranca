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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.OneToOne;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.Logger;
import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;dynamic-insertion&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class ReplaceContentRule extends Rule {
	
	private static final long serialVersionUID = 1L;

	@Transient
	private Pattern pattern;
	
	private String replacement;
	
	@Transient
	private Pattern contentType;
	
	@Transient
	private Pattern path;
	
	@OneToOne
	private UrlPath pattern1;
	
	@OneToOne
	private UrlPath contentType1;
	
	@OneToOne
	private UrlPath path1;
	
	public ReplaceContentRule(){
		pattern1 = new UrlPath();
		contentType1 = new UrlPath();
		path1 = new UrlPath();
	}
	
	public ReplaceContentRule(String id, Pattern pattern, String replacement, Pattern contentType, Pattern path) {
		this.pattern = pattern;
		this.replacement = replacement;
		this.path = path;
		this.contentType = contentType;
		//setId(id);
	}

	/*
	 * Use regular expressions with capturing parentheses to perform replacement.
	 */

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		/*
		 * First early fail: if the URI doesn't match the paths we're interested in.
		 */
		String uri = request.getRequestURI();
		if ( path != null && ! path.matcher(uri).matches() ) {
			return new DoNothingAction();
		}
		
		/*
		 * Second early fail: if the content type is one we'd like to search for output patterns.
		 */

		if ( contentType != null ) {
			if ( response.getContentType() != null && ! contentType.matcher(response.getContentType()).matches() ) {
				return new DoNothingAction();
			}
		}

		byte[] bytes = null;

		try {
			bytes = response.getInterceptingServletOutputStream().getResponseBytes();
		} catch (IOException ioe) {
			log(request,"Error matching pattern '" + pattern.pattern() + "', IOException encountered (possibly too large?): " + ioe.getMessage() + " (in response to URL: '" + request.getRequestURL() + "')");
			return new DoNothingAction(); // yes this is a fail open!
		}

		
		try {

			String s = new String(bytes,response.getCharacterEncoding());

			Matcher m = pattern.matcher(s);
			String canary = m.replaceAll(replacement);
			
			try {
				
				if ( ! s.equals(canary) ) {
					response.getInterceptingServletOutputStream().setResponseBytes(canary.getBytes(response.getCharacterEncoding()));
					logger.debug(Logger.SECURITY_SUCCESS, "Successfully replaced pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "'");
				}
				
			} catch (IOException ioe) {
				logger.error(Logger.SECURITY_FAILURE, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + ioe.getMessage() + "]");
			}

		} catch(UnsupportedEncodingException uee) {
			logger.error(Logger.SECURITY_FAILURE, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + uee.getMessage() + "]");
		}

		return new DoNothingAction();
	}

	public String getReplacement() {
		return replacement;
	}

	public void setReplacement(String replacement) {
		this.replacement = replacement;
	}

	public UrlPath getPattern1() {
		return pattern1;
	}

	public void setPattern1(UrlPath pattern1) {
		this.pattern1 = pattern1;
	}

	public UrlPath getContentType1() {
		return contentType1;
	}

	public void setContentType1(UrlPath contentType1) {
		this.contentType1 = contentType1;
	}

	public UrlPath getPath1() {
		return path1;
	}

	public void setPath1(UrlPath path1) {
		this.path1 = path1;
	}

}
