/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.authentication.sts;

import java.io.File;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseProperty;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.web.XWikiResponse;
import org.xwiki.test.AbstractComponentTestCase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class XWikiSTSAuthenticatorTest extends AbstractComponentTestCase {
	static Log log = LogFactory.getLog(XWikiSTSAuthenticatorTest.class);
	XWikiContext context;
	XWikiSTSAuthenticator auth;
	XWiki wiki, wikispy;

	@SuppressWarnings("deprecation")
	@Before
	public void setUp() throws Exception {
		Utils.setComponentManager(getComponentManager());
		Cookie cookie = new Cookie("username", "student");
		wiki = mock(XWiki.class);
		context = mock(XWikiContext.class);
		XWikiRequest request = mock(XWikiRequest.class);
		HttpSession session = mock(HttpSession.class);
		XWikiDocument doc = mock(XWikiDocument.class);
		BaseObject baseObj = mock(BaseObject.class);
		BaseProperty baseProp = mock(BaseProperty.class);

		XWikiSTSAuthenticatorProperties props = new XWikiSTSAuthenticatorProperties();
		auth = new XWikiSTSAuthenticator();

		when(context.getRequest()).thenReturn(request);
		when(request.getCookie(any(String.class))).thenReturn(cookie);
		when(request.getHttpServletRequest()).thenReturn(request);
		when(request.getSession(true)).thenReturn(session);
		when(request.getSession()).thenReturn(session);

		XWikiResponse response = mock(XWikiResponse.class);
		when(context.getResponse()).thenReturn(response);

		when(session.getAttribute("sts_user")).thenReturn("123123-12345");
		when(context.getWiki()).thenReturn(wiki);
		when(wiki.Param("xwiki.authentication.sts.auth_field")).thenReturn("sts_user");
		when(wiki.Param("xwiki.authentication.sts.stsauthclass_id_field")).thenReturn("nameid");
		when(wiki.exists(anyString(), (XWikiContext) anyObject())).thenReturn(false, true);
		List<Object> xwikilist0 = new ArrayList<Object>(0);
		List<Object> xwikilist1 = new ArrayList<Object>(1);
		// xwikilist1.add("ValdisVitolins");

		when(wiki.search(anyString(), (XWikiContext) anyObject())).thenReturn(xwikilist0, xwikilist1);

		when(wiki.getDocument(anyString(), (XWikiContext) anyObject())).thenReturn(doc);

		when(wiki.Param("xwiki.authentication.sts.wreply_host")).thenReturn("aha");
		when(wiki.Param("xwiki.authentication.sts.wreply_page")).thenReturn("1");
		// when(
		// wiki.Param(matches("(.*id.*|subject|issuer|entity|reply|url|uri)")))
		// .thenReturn("0");

		when(doc.getObject(anyString(), anyInt())).thenReturn(baseObj);
		when(doc.getObject(anyString())).thenReturn(baseObj);
		when(doc.newObject(anyString(), (XWikiContext) anyObject())).thenReturn(baseObj);

		when(baseObj.get(anyString())).thenReturn(baseProp);
		when(baseProp.getValue()).thenReturn("propValue");

		when(wiki.getUniquePageName(anyString(), anyString(), (XWikiContext) anyObject())).thenReturn("ValdisVitolins");

		File testFile = new File("testToken.xml");
		String testToken = FileUtils.readFileToString(testFile);
		when(request.getParameter("wresult")).thenReturn(testToken);
		when(request.getParameter(anyString())).thenReturn("1");
		when(props.getFieldMapping(context)).thenReturn("first_name=givenname,last_name=surname");
		when(props.getUsernameRule(context)).thenReturn("first_name,last_name");
		when(props.getWct(context)).thenReturn("1", "0");
		when(props.getWctx(context)).thenReturn("1", "0");
		when(props.getWfresh(context)).thenReturn("1");

	}

	@Override
	@After
	public void tearDown() throws Exception {
		Utils.setComponentManager(null);
		super.tearDown();
	}

	@Test
	public void showLoginTest() {
		log.info(context.toString());
		try {
			log.info("showLogin()");
			auth.showLogin(context);
			log.info("checkAuth(context)");
		} catch (XWikiException e) {
			log.error("showLoginTest error" + e);
		}
	}

	@Test
	public void checkAuthTest() {
		try {
			// checkSTSResponse returns false
			assertTrue("checkAuth with checkSTSResponse()==false failed", auth.checkAuth(context) instanceof XWikiUser);
			assertTrue("checkAuth with checkSTSResponse()==true failed", auth.checkAuth(context) instanceof XWikiUser);
			log.info("checkAuth('username', 'password', '', 'context')");
			assertTrue("checkAuth('username', 'password', '', 'context') failed",
					auth.checkAuth("username", "password", "", context) instanceof XWikiUser);
		} catch (XWikiException e) {
			log.error("checkAuthTest error" + e);
		}

	}

	@Test
	public void authenticateTest() {
		try {
			log.info("authenticate('username', 'password', 'context')");
			auth.authenticate("username", "password", context);
		} catch (XWikiException e) {
			log.error("authenticateTest error" + e);
		}

	}

	@Test
	public void checkSTSResponseTest() {
		try {
			log.info("checkSTSResponse(context) negative test");
			assertFalse("checkSTSResponse(context) negative test failed", auth.checkSTSResponse(context));
			log.info("checkSTSResponse(context) new user");
			assertTrue("checkSTSResponse(context) new user failed", auth.checkSTSResponse(context));
			assertTrue("checkSTSResponse(context) update user failed", auth.checkSTSResponse(context));
		} catch (XWikiException e) {
			log.error("checkSTSResponseTest error" + e);
		}
	}
}
