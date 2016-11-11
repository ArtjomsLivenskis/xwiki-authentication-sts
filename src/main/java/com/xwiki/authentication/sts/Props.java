package com.xwiki.authentication.sts;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.xpn.xwiki.XWikiContext;

/**
 * This class have only one method which is loading certificate from filename in 
 * xwiki.authentication.sts.cert_filename METHADATA. 
 * It is using to load - serificate from file opposite to first implemented method,
 * which was loading certificate from metadata. It trays to find filename stored in
 * xwiki.authentication.sts.cert_filename and then to load it. If succeed - returns X509Certificate
 * else returns null value. Class extends XWikiSTSAuthenticatorProperties to add getCertificate
 * to standart implamentation.
 * 
 * @version 1.0
 */

class Props extends XWikiSTSAuthenticatorProperties {

	X509Certificate getCertificate(XWikiContext context) {
	    /**
		* filename - String contaings loaded from "xwiki.authentication.sts.cert_filename" parametr
		*/
		String filename = null;
		/**
		* File Input stream - to read our certificate
		*/
		FileInputStream fr = null;
		/**
		* cert - X509Certificate - hold some context
		*/
		X509Certificate cert = null;
		try {
			filename = context.getWiki().Param(
					"xwiki.authentication.sts.cert_filename");
			fr = new FileInputStream(filename);
			CertificateFactory cf;
			cf = CertificateFactory.getInstance("X509");
			log.debug("\n");
			log.debug("XWikiSTSAuthenticatorProperties: Cert returned, should use it to validate with it");
			cert = (X509Certificate) cf.generateCertificate(fr);

		} catch (FileNotFoundException e) {
			log.debug("\n");
			log.debug("XWikiSTSAuthenticatorProperties: cert '" + filename
					+ "' not found: " + e);
		} catch (CertificateException e) {
			log.debug("\n");
			log.debug("XWikiSTSAuthenticatorProperties: Could not create cert from '"
					+ filename + "': " + e);
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
