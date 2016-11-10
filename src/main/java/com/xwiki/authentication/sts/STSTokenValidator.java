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
 * 
 * Part of the code in this file is copied from: https://github.com/auth10/auth10-java
 * which is based on Microsoft libraries in: https://github.com/WindowsAzure/azure-sdk-for-java-samples. 
 * 
 */

package com.xwiki.authentication.sts;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityTestHelper;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/*
 For new authentication method to work  this lines in xwiki/WEB-INF/xwiki.cfg were changed

 < xwiki.authentication.sts.issuer=http://www.latvija.lv/trust
---
> xwiki.authentication.sts.issuer=http://www.latvija.lv/sts
705c705
< xwiki.authentication.sts.entity_id=http://www.latvija.lv/trust
---
> xwiki.authentication.sts.entity_id=http://www.latvija.lv/sts
707c707
< xwiki.authentication.sts.issuer_dn=CN=IVIS Root CA
---
> xwiki.authentication.sts.issuer_dn=CN=VISS Root CA, DC=viss, DC=int
709c709
< xwiki.authentication.sts.subject_dns=EMAILADDRESS=cisu.help@vraa.gov.lv, CN=IVIS.LVP.STS_PROD, OU=VPISD, O=VRAA, L=Riga, ST=Riga, C=LV
---
> xwiki.authentication.sts.subject_dns=EMAILADDRESS=cisu.help@vraa.gov.lv, CN=VISS.LVP.STS, OU=VPISD, O=VRAA, L=Riga, ST=Riga, C=LV
*/
/**
 * Validates STSToken
 * Have main method validate to validate token and have some utility private methods helping to
 * validation process
 * 
 * @version 1.0
 */
@SuppressWarnings("deprecation")
public class  STSTokenValidator {
	/**
     * Log log - log - from LogFactory 
     */
	private static Log log = LogFactory.getLog(STSTokenValidator.class);
	/**
     * max ClockSkew - using to check time intervals / Before / After as a deviation
     */
	private int maxClockSkew;
	/**
     * max ClockSkew - max time interval in which may be a value
     */
	private List<String> trustedSubjectDNs;
	/**
     * max ClockSkew - http/https urls - 
     */
	private List<URI> audienceUris;
	/**
     * max ClockSkew - http/https urls - 
     */
	private boolean validateExpiration = true;
	/**
	* entityId - ID of the entity used for set entity id of the sertificate
	*/
	private static String entityId;
	/**
	* IssuerDN value from the certificate (will be extracted from samlToken)
	*/
	private String issuerDN;
	/**
	 * context
	 */
	private String context;
	/** 
	 * Name of Issuer DN - getIssuerDN
	 */
	private String issuer;
	/** 
	 * certificate made from SAMLToken
	 */
	X509Certificate certificate;

	public STSTokenValidator() throws ConfigurationException {
		this(new ArrayList<String>(), new ArrayList<URI>());
	}
	
	
	/**
	 * <b>STSTokenValidator</b> - constructor for making  STSTokenValidator
	 *
	 * @param trustedSubjectDNs List<String>,
	 * @param audienceUris List<URI>
	 * @throws ConfigurationException - exception of open SAML's configuration
	 */
	public STSTokenValidator(List<String> trustedSubjectDNs, List<URI> audienceUris) throws ConfigurationException {
		super();
		this.trustedSubjectDNs = trustedSubjectDNs;
		this.audienceUris = audienceUris;
		DefaultBootstrap.bootstrap();
	}

	public void setSubjectDNs(List<String> subjectDNs) {
		this.trustedSubjectDNs = subjectDNs;
	}

	public void setAudienceUris(List<URI> audienceUris) {
		this.audienceUris = audienceUris;
	}

	public void setValidateExpiration(boolean value) {
		this.validateExpiration = value;
	}

	public void setEntityId(String value) {
		entityId = value;
	}
	
    /**
     * validate - Validate Token
     * 
     * @param envelopedToken String
     * @return List<STSClaim> 
     * @throws ParserConfigurationException, SAXException, IOException, STSException, ConfigurationException, CertificateException, KeyException, SecurityException, ValidationException, UnmarshallingException, URISyntaxException, NoSuchAlgorithmException
     */
	public List<STSClaim> validate(String envelopedToken) throws ParserConfigurationException, SAXException,
			IOException, STSException, ConfigurationException, CertificateException, KeyException, SecurityException,
			ValidationException, UnmarshallingException, URISyntaxException, NoSuchAlgorithmException {

		SignableSAMLObject samlToken;
		boolean trusted = false;

		// Check token metadata
		if (envelopedToken.contains("RequestSecurityTokenResponse")) {
			samlToken = getSamlTokenFromRstr(envelopedToken);
		} else {
			samlToken = getSamlTokenFromSamlResponse(envelopedToken);
		}

		log.debug("\n===== envelopedToken ========\n" + samlToken.getDOM().getTextContent() + "\n==========");
		String currentContext = getAttrVal(envelopedToken, "t:RequestSecurityTokenResponse", "Context");
		if (!context.equals(currentContext)) {
			throw new STSException("Wrong token Context. Suspected: " + context + " got: " + currentContext);
		}

		if (this.validateExpiration) {
			Instant created = new Instant(getElementVal(envelopedToken, "wsu:Created"));
			Instant expires = new Instant(getElementVal(envelopedToken, "wsu:Expires"));
			if (!checkExpiration(created, expires)) {
				throw new STSException("Token Created or Expires elements have been expired");
			}
		} else {
			log.warn("Token time was not validated. To validate, set xwiki.authentication.sts.wct=1");
		}

		if (certificate == null) {
			log.debug("\n");
			log.debug("STSTokenValidator: cert is null, using old method");

			if (issuer != null && issuerDN != null && trustedSubjectDNs.size() != 0) {

				if (!issuer.equals(getAttrVal(envelopedToken, "saml:Assertion", "Issuer"))) {
					throw new STSException("Wrong token Issuer");
				}

				// Check SAML assertions
				if (!validateIssuerDN(samlToken, issuerDN)) {
					throw new STSException("Wrong token IssuerDN");
				}

				for (String subjectDN : this.trustedSubjectDNs) {
					trusted |= validateSubjectDN(samlToken, subjectDN);
				}

				if (!trusted) {
					throw new STSException("Wrong token SubjectDN");
				}
			} else {
				log.debug("\n");
				log.debug("STSTokenValidator: Nothing to validate against");
				throw new STSException("Nothing to validate against");
			}

		} else {
			log.debug("\n");
			log.debug("STSTokenValidator: Using cert equals");
			if (!certificate.equals(certFromToken(samlToken))) {
				throw new STSException("Local certificate didn't match the user suplied one");
			}
		}

		String address = null;
		if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
			address = getAudienceUri((org.opensaml.saml1.core.Assertion) samlToken);
		}

		URI audience = new URI(address);

		boolean validAudience = false;
		for (URI audienceUri : audienceUris) {
			validAudience |= audience.equals(audienceUri);
		}

		if (!validAudience) {
			throw new STSException(
					String.format("The token applies to an untrusted audience: %s", new Object[] { audience }));
		}

		List<STSClaim> claims = null;
		if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
			claims = getClaims((org.opensaml.saml1.core.Assertion) samlToken);
		}

		if (this.validateExpiration) {
			if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
				Instant notBefore = ((org.opensaml.saml1.core.Assertion) samlToken).getConditions().getNotBefore()
						.toInstant();
				Instant notOnOrAfter = ((org.opensaml.saml1.core.Assertion) samlToken).getConditions().getNotOnOrAfter()
						.toInstant();
				if (!checkExpiration(notBefore, notOnOrAfter)) {
					throw new STSException("Token SAML Conditions: NotBefore or NotOnOrAfter has been expired");
				}
			}
		}

		// Check token certificate and signature
		boolean valid = validateToken(samlToken);
		if (!valid) {
			throw new STSException("Invalid signature");
		}

		return claims;
	}
	
	 /**
     * getSamlTokenFromSamlResponse (String samlResponse)
     * 
     * Function is getting samlResponse String - 
     * SAML - Object is object of Security Assertion Markup Languages type is an XML-based, 
     * open-standard data format for exchanging authentication and authorization data between parties
     * And is returning SignableSAMLObject on success or throws exception on fault
     *      
     * @param samlResponse - SAML Text Response (String)
     * 
     * @return SignableSAMLObject (Security Assertion Markup Language) 
     * @throws ParserConfigurationException - Indicates a serious configuration error,
     * @throws SAXException - Encapsulate a general SAX error or warning, IOException, 
     * @throws UnmarshallingException - thrown whenever an IOException is thrown during the unmarshalling process of request/response from the wire. 
     */
	private static SignableSAMLObject getSamlTokenFromSamlResponse(String samlResponse)
			throws ParserConfigurationException, SAXException, IOException, UnmarshallingException {
		Document document = getDocument(samlResponse);

		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory()
				.getUnmarshaller(document.getDocumentElement());
		org.opensaml.saml2.core.Response response = (org.opensaml.saml2.core.Response) unmarshaller
				.unmarshall(document.getDocumentElement());
		SignableSAMLObject samlToken = (SignableSAMLObject) response.getAssertions().get(0);

		return samlToken;
	}
	
    /**
     * getSamlTokenFromRstr (String rstr) - get SAML Token from some XML Document
     * 
     * @param rstr - String -  XML - Document's string from which will be extracted an information of a SamlToken
     * @return SignableSAMLObject - an instance of SAMLObject (Security Assertion Markup Language) 
     * @throws ParserConfigurationException, SAXException, IOException, UnmarshallingException, STSException
     * 
     */
	private static SignableSAMLObject getSamlTokenFromRstr(String rstr)
			throws ParserConfigurationException, SAXException, IOException, UnmarshallingException, STSException {
		Document document = getDocument(rstr);

		String xpath = "//*[local-name() = 'Assertion']";

		NodeList nodes = null;

		try {
			nodes = org.apache.xpath.XPathAPI.selectNodeList(document, xpath);
		} catch (TransformerException e) {
			e.printStackTrace();
		}

		if (nodes.getLength() == 0) {
			throw new STSException("SAML token was not found");
		}

		Element samlTokenElement = (Element) nodes.item(0);
		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(samlTokenElement);
		SignableSAMLObject samlToken = (SignableSAMLObject) unmarshaller.unmarshall(samlTokenElement);

		return samlToken;
	}
	
    
    /**
     * Function gets AudienceUri String from org.opensaml.saml1.core.Assertion samlAssertion
     * 
     * @param samlAssertion - A Security Assertion Markup Language (SAML) authorization assertion contains 
     * @return String AudienceUri - extracted from samlAssertion.getConditions().getAudienceRestrictionConditions().get(0)
	 *	.getAudiences().get(0);
     * 
     */
	private static String getAudienceUri(org.opensaml.saml1.core.Assertion samlAssertion) {
		org.opensaml.saml1.core.Audience audienceUri = samlAssertion.getConditions().getAudienceRestrictionConditions()
				.get(0).getAudiences().get(0);
		String audienceUriStr = audienceUri.getUri();
		log.trace("AudienceUri: " + audienceUriStr);
		return audienceUriStr;
	}

    /**
     * checkExpiration(Instant notBefore, Instant notOnOrAfter)
     * Function checks that date now is after (notBefore parameter)
     * and now is before notOnOrAfter (calculating Skew - which is new Duration(this.maxClockSkew) object )
     *      
     * @param notBefore  Instant now is after not Before (plus skew)
     * @param notOnOrAfter Instant now is before notOnOrAfter (minus skew)
     * @return true - if check  - is ok, or false if check is fault
     */
	private boolean checkExpiration(Instant notBefore, Instant notOnOrAfter) {
		Instant now = new Instant();
		Duration skew = new Duration(maxClockSkew);
		log.debug("Time expiration. Now:" + now + " now+sqew: " + now.plus(skew) + " now-sqew: " + now.minus(skew)
				+ " notBefore: " + notBefore + " notAfter: " + notOnOrAfter);
		if (now.plus(skew).isAfter(notBefore) && now.minus(skew).isBefore(notOnOrAfter)) {
			log.debug("Time is in range");
			return true;
		}
		return false;
	}
	
	 /**
     * validateToken(SignableSAMLObject samlToken)
     * Validates Token from SAMLlObject - returns boolen
     * @param samlToken SignableSAMLObject
     * @return boolean valid => true, not valid => false
     */
	private static boolean validateToken(SignableSAMLObject samlToken) throws SecurityException, ValidationException,
			ConfigurationException, UnmarshallingException, CertificateException, KeyException {

		// Validate XML structure
		samlToken.validate(true);

		Signature signature = samlToken.getSignature();
		// KeyInfo keyInfo = signature.getKeyInfo();
		// X509Certificate certificate = (X509Certificate)
		// KeyInfoHelper.getCertificates(keyInfo).get(0);
		X509Certificate certificate = certFromToken(samlToken);

		// Certificate data
		log.debug("certificate issuerDN: " + certificate.getIssuerDN());
		log.debug("certificate issuerUniqueID: " + certificate.getIssuerUniqueID());
		log.debug("certificate issuerX500Principal: " + certificate.getIssuerX500Principal());
		log.debug("certificate notBefore: " + certificate.getNotBefore());
		log.debug("certificate notAfter: " + certificate.getNotAfter());
		log.debug("certificate serialNumber: " + certificate.getSerialNumber());
		log.debug("certificate sigAlgName: " + certificate.getSigAlgName());
		log.debug("certificate sigAlgOID: " + certificate.getSigAlgOID());
		log.debug("certificate signature: " + new String(certificate.getSignature()));
		log.debug("certificate issuerX500Principal: " + certificate.getIssuerX500Principal().toString());
		log.debug("certificate publicKey: " + certificate.getPublicKey());
		log.debug("certificate subjectDN: " + certificate.getSubjectDN());
		log.debug("certificate sigAlgOID: " + certificate.getSigAlgOID());
		log.debug("certificate version: " + certificate.getVersion());

		BasicX509Credential cred = new BasicX509Credential();
		cred.setEntityCertificate(certificate);

		// Credential data
		cred.setEntityId(entityId);
		log.debug("cred entityId: " + cred.getEntityId());
		log.debug("cred usageType: " + cred.getUsageType());
		log.debug("cred credentalContextSet: " + cred.getCredentalContextSet());
		log.debug("cred hashCode: " + cred.hashCode());
		log.debug("cred privateKey: " + cred.getPrivateKey());
		log.debug("cred publicKey: " + cred.getPublicKey());
		log.debug("cred secretKey: " + cred.getSecretKey());
		log.debug("cred entityCertificateChain: " + cred.getEntityCertificateChain());

		ArrayList<Credential> trustedCredentials = new ArrayList<Credential>();
		trustedCredentials.add(cred);

		CollectionCredentialResolver credResolver = new CollectionCredentialResolver(trustedCredentials);
		KeyInfoCredentialResolver kiResolver = SecurityTestHelper.buildBasicInlineKeyInfoResolver();
		ExplicitKeySignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);

		CriteriaSet criteriaSet = new CriteriaSet();
		criteriaSet.add(new EntityIDCriteria(entityId));

		Base64 decoder = new Base64();
		// In trace mode write certificate in the file
		if (log.isTraceEnabled()) {
			String certEncoded = new String(decoder.encode(certificate.getEncoded()));
			try {
				FileUtils.writeStringToFile(new File("/tmp/Certificate.cer"),
						"-----BEGIN CERTIFICATE-----\n" + certEncoded + "\n-----END CERTIFICATE-----");
				log.trace("Certificate file was saved in: /tmp/Certificate.cer");
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}
		return engine.validate(signature, criteriaSet);
	}
	

    /**
    * validateSubjectDN(SignableSAMLObject samlToken, String subjectName)
    * Validates the subject (subject distinguished name) value from the certificate. 
    * @param samlToken SignableSAMLObject saml Token
    * @param subjectName subjectNamme name to Validate
    * @return boolean valid => true, not valid => false
    */
	private static boolean validateSubjectDN(SignableSAMLObject samlToken, String subjectName)
			throws UnmarshallingException, ValidationException, CertificateException {
		Signature signature = samlToken.getSignature();
		KeyInfo keyInfo = signature.getKeyInfo();
		X509Certificate pubKey = KeyInfoHelper.getCertificates(keyInfo).get(0);
		String subjectDN = pubKey.getSubjectDN().getName();
		log.trace("passed subjectName: '" + subjectName + "' certificate SubjectDN: '" + subjectDN);
		return subjectDN.equals(subjectName);
	}
	

    /**
    * validateIssuerDN(SignableSAMLObject samlToken, String subjectName)
    * Validates IssuerDN value from the certificate (extracted from samlToken). 
    * @param samlToken SignableSAMLObject - saml Token
    * @param issuerName issuer name validate to
    * @return valid  boolean => true, not valid => false
    * @throws UnmarshallingException, ValidationException, CertificateException 
    */
	private static boolean validateIssuerDN(SignableSAMLObject samlToken, String issuerName)
			throws UnmarshallingException, ValidationException, CertificateException {

		Signature signature = samlToken.getSignature();
		KeyInfo keyInfo = signature.getKeyInfo();
		X509Certificate pubKey = KeyInfoHelper.getCertificates(keyInfo).get(0);
		String issuer = pubKey.getIssuerDN().getName();
		log.trace("passed issuerName: '" + issuerName + "' certificate IssuerDN: '" + issuer + "'");
		return issuer.equals(issuerName);
	}
	
    /**
    * getClaims(org.opensaml.saml1.core.Assertion samlAssertion)
    * Get's List of STSClaims according to samlAssertion
    * @param samlAssertion org.opensaml.saml1.core.Assertion
    * @return ArrayList<STSClaim> (Claims-based identity is a common way for applications to acquire the identity information they need about users inside their organization)
    * @throws SecurityException, ValidationException, ConfigurationException, UnmarshallingException, CertificateException, KeyException
    * @throws UnmarshallingException, ValidationException, CertificateExceptio @throws UnmarshallingException, ValidationException, CertificateException n 
    */
	private static List<STSClaim> getClaims(org.opensaml.saml1.core.Assertion samlAssertion) throws SecurityException,
			ValidationException, ConfigurationException, UnmarshallingException, CertificateException, KeyException {

		ArrayList<STSClaim> claims = new ArrayList<STSClaim>();

		List<org.opensaml.saml1.core.AttributeStatement> attributeStmts = samlAssertion.getAttributeStatements();

		for (org.opensaml.saml1.core.AttributeStatement attributeStmt : attributeStmts) {
			List<org.opensaml.saml1.core.Attribute> attributes = attributeStmt.getAttributes();

			for (org.opensaml.saml1.core.Attribute attribute : attributes) {
				String claimType = attribute.getAttributeNamespace() + "/" + attribute.getAttributeName();
				String claimValue = getValueFrom(attribute.getAttributeValues());
				claims.add(new STSClaim(claimType, claimValue));
			}
		}
		log.trace("Claims: " + claims.toString());
		return claims;
	}
	
    /*
    * getValueFrom(List<XMLObject> attributeValues)
    * Gets all atribute's values from a list of XML objects
    * @param attributeValues List<XMLObject>
    * @return buffer.toString() - converted to string buffer of XML attribute's values
    */
	private static String getValueFrom(List<XMLObject> attributeValues) {

		StringBuffer buffer = new StringBuffer();

		for (XMLObject value : attributeValues) {
			if (buffer.length() > 0)
				buffer.append(',');
			buffer.append(value.getDOM().getTextContent());
		}
		log.trace("attributeValues: " + buffer.toString());
		return buffer.toString();
	}

	

    /**
    * getDocument(String doc)
    * Parse document from string
    * @param doc String string containing info for document builder parser
    * @return Document - parsed from input string document 
    */
	private static Document getDocument(String doc) throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder documentbuilder = factory.newDocumentBuilder();
		return documentbuilder.parse(new InputSource(new StringReader(doc)));
	}

    /**
    * getAttrVal(String envelopedToken, String element, String attribute)
    * Gets value of Document value contained in evelopedToken
    * @param element String element to get value for
    * @param attribute String attribute to get value for
    * @return value String of element's attribute
    */
	private String getAttrVal(String envelopedToken, String element, String attribute)
			throws ParserConfigurationException, SAXException, IOException {
		Document doc = getDocument(envelopedToken);
		String val = doc.getElementsByTagName(element).item(0).getAttributes().getNamedItem(attribute).getNodeValue();
		return val;
	}
	
    /**
    * getElementVal(String envelopedToken, String element)
    * Gets value of Document value contained in evelopedToken
    * @param element String  element to get value for
    * @param envelopedToken enveloped Token
    * @throws throws ParserConfigurationException, SAXException, IOException 
    * @return String - value of element's attribute
    */
	private String getElementVal(String envelopedToken, String element)
			throws ParserConfigurationException, SAXException, IOException {
		Document doc = getDocument(envelopedToken);
		String val = doc.getElementsByTagName(element).item(0).getTextContent();
		return val;
	}


	public void setIssuerDN(String issuerDN) {
		this.issuerDN = issuerDN;
	}

	public void setContext(String context) {
		this.context = context;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public void setMaxClockSkew(int maxClockSkew) {
		this.maxClockSkew = maxClockSkew;
	}

	public void setCertificate(X509Certificate cert) {
		this.certificate = cert;
	}

	/**
    * X509Certificate certFromToken(SignableSAMLObject token)
    * @param token SignableSAMLObject input token with sertificate inside
    * @throws throws ParserConfigurationException, SAXException, IOException 
    * @return X509Certificate - certificate extracted from SAMLToken
    */
	private static X509Certificate certFromToken(SignableSAMLObject token) {
		try {
			return KeyInfoHelper.getCertificates(token.getSignature().getKeyInfo()).get(0);
		} catch (CertificateException e) {
			return null;
		}
	}
}
