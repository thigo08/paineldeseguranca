/*
 Demoiselle Framework
 Copyright (C) 2013 SERPRO
 ============================================================================
 This file is part of Demoiselle Framework.
 Demoiselle Framework is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public License version 3
 as published by the Free Software Foundation.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU Lesser General Public License version 3
 along with this program; if not,  see <http://www.gnu.org/licenses/>
 or write to the Free Software Foundation, Inc., 51 Franklin Street,
 Fifth Floor, Boston, MA  02110-1301, USA.
 ============================================================================
 Este arquivo é parte do Framework Demoiselle.
 O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 do Software Livre (FSF).
 Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 para maiores detalhes.
 Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 ou escreva para a Fundação do Software Livre (FSF) Inc.,
 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */
package org.owasp.esapi.waf.view;

import javax.inject.Inject;

import org.owasp.esapi.waf.business.DetectOutboundContentRuleBC;
import org.owasp.esapi.waf.business.UrlPathBC;
import org.owasp.esapi.waf.rules.DetectOutboundContentRule;

import br.gov.frameworkdemoiselle.annotation.PreviousView;
import br.gov.frameworkdemoiselle.stereotype.ViewController;
import br.gov.frameworkdemoiselle.template.AbstractEditPageBean;
import br.gov.frameworkdemoiselle.transaction.Transactional;

@ViewController
@PreviousView("./detectoutboundcontentrule_list.jsf")
public class DetectOutboundContentRuleEditMB extends AbstractEditPageBean<DetectOutboundContentRule, Long> {

	private static final long serialVersionUID = 1L;
	
	//private DataModel<UrlPath> pathexceptions;
	
	@Inject
	private DetectOutboundContentRuleBC detectOutboundContentRuleBC;
	
	@Inject
	private UrlPathBC urlPathBC;
	
	@Override
	@Transactional
	public String delete() {
		this.detectOutboundContentRuleBC.delete(getId());
		return getPreviousView();
	}
	
	@Override
	@Transactional
	public String insert() {
		DetectOutboundContentRule detectOutboundContentRule = getBean();
		
		urlPathBC.insert(detectOutboundContentRule.getContentType1());
		urlPathBC.insert(detectOutboundContentRule.getPattern1());
		urlPathBC.insert(detectOutboundContentRule.getUri1());
		
		this.detectOutboundContentRuleBC.insert(getBean());
		return getPreviousView();
	}
	
	
	@Override
	@Transactional
	public String update() {
		this.detectOutboundContentRuleBC.update(getBean());
		return getPreviousView();
	}
	
//	public DataModel<UrlPath> getPathExceptions() {
//		if (pathexceptions == null) {
//			pathexceptions = new ListDataModel<UrlPath>(getBean().getExceptions());
//		}
//
//		return pathexceptions;
//	}
//	
//	public void addPathException() {
//		getBean().getExceptions().add(new UrlPath());
//	}
//
//	public void deletePathException() {
//		getBean().getExceptions().remove(getPathExceptions().getRowData());
//	}

	@Override
	protected DetectOutboundContentRule handleLoad(Long id) {
		return this.detectOutboundContentRuleBC.load(id);
	}
		
}