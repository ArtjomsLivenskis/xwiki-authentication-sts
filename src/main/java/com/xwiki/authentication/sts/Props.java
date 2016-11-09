package com.xwiki.authentication.sts;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.xpn.xwiki.XWikiContext;

class Props extends XWikiSTSAuthenticatorProperties {

	X509Certificate getCertificate(XWikiContext context) {
		String filename = null;
		FileInputStream fr = null;
		X509Certificate cert = null;
		try {
			filename = context.getWiki().Param("xwiki.authentication.sts.cert_filename");
			fr = new FileInputStream(filename);
			CertificateFactory cf;
			cf = CertificateFactory.getInstance("X509");
			log.debug("\n");
			log.debug("XWikiSTSAuthenticatorProperties: Cert returned, should use it to validate with it");
			cert = (X509Certificate) cf.generateCertificate(fr);

		} catch (FileNotFoundException e) {
			log.debug("\n");
			log.debug("XWikiSTSAuthenticatorProperties: cert '" + filename + "' not found: " + e);
		} catch (CertificateException e) {
			log.debug("\n");
			log.debug("XWikiSTSAuthenticatorProperties: Could not create cert from '" + filename + "': " + e);
		} finally {
				if (fr != null)
					try {
						fr.close();
					} catch (IOException e) {
						log.error(e);
					}
		}
		return cert;
	}
}
