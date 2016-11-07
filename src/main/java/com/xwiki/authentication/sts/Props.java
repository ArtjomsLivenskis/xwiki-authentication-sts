package com.xwiki.authentication.sts;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.xpn.xwiki.XWikiContext;

class Props extends XWikiSTSAuthenticatorProperties {

	X509Certificate getCertificate(XWikiContext context) {
		String filename = null;
		FileInputStream fr;
		try {
			filename = context.getWiki().Param("xwiki.authentication.sts.cert_filename");
			fr = new FileInputStream(filename);
			CertificateFactory cf;
			try {
				cf = CertificateFactory.getInstance("X509");
				log.debug("\n");
				log.debug("XWikiSTSAuthenticatorProperties: Cert returned, should use it to validate with it");
				return (X509Certificate) cf.generateCertificate(fr);
			} catch (CertificateException e) {
				log.debug("\n");
				log.debug("XWikiSTSAuthenticatorProperties: Could not create cert from '" + filename + "'");
				// return null;
			}
		} catch (FileNotFoundException e) {
			log.debug("\n");
			log.debug("XWikiSTSAuthenticatorProperties: cert '" + filename + "' not found");
			// return null;
		}
		return null;
	};
}
