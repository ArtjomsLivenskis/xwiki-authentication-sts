package com.xwiki.authentication.sts;

import static org.junit.Assert.*;

import static org.mockito.Mockito.*;

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseProperty;
import com.xpn.xwiki.web.XWikiRequest;

public class PropsTest {
	Props props;
	XWiki wiki;
	XWikiContext context;
	X509Certificate cer;

	
	@Before
	public void setUp(){
		props = new Props();
		wiki = mock(XWiki.class);
		context = mock(XWikiContext.class);
		when(context.getWiki()).thenReturn(wiki);
	}

	@Test
	public void testPosGetCertificate() {
		when(wiki.Param("xwiki.authentication.sts.cert_filename")).thenReturn("VISS.LVP.STS.cer");
		props.getCertificate(context);
		cer = props.getCertificate(context);
		assertEquals(true, cer instanceof X509Certificate);
	}

	@Test
	public void testNotFoundGetCertificate() {
		when(wiki.Param("xwiki.authentication.sts.cert_filename")).thenReturn("just.some.certificate.which is not there");
		cer = props.getCertificate(context);
		assertEquals(false, cer instanceof X509Certificate);
	}

	@Test
	public void testCorruptedGetCertificate() {
		when(wiki.Param("xwiki.authentication.sts.cert_filename")).thenReturn("corrupted.cer");
		cer = props.getCertificate(context);
		assertEquals(false, cer instanceof X509Certificate);
	}

}
