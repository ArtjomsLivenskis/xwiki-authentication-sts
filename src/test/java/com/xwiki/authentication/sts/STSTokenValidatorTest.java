package com.xwiki.authentication.sts;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class STSTokenValidatorTest {
	private static Log log = LogFactory.getLog(STSTokenValidatorTest.class);
	static File testFile;
	static STSTokenValidator validator;
	static String context;
	static String issuer;
	static String testToken;
	static String entityId;
	static String issuerDN;
	static List<String> subjectDNs;
	static List<URI> audienceUris;
	static boolean validateExpiration;
	static int maxClockSkew = 60000;
	static STSErrorCollector errorCollector = new STSErrorCollector();

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		validator = new STSTokenValidator();
		subjectDNs = new ArrayList<String>();
		audienceUris = new ArrayList<URI>();

		// Common test settings
		testFile = new File("testToken.xml");
		subjectDNs
				.add("EMAILADDRESS=cisu.help@vraa.gov.lv, CN=VISS.LVP.STS, OU=VPISD, O=VRAA, L=Riga, ST=Riga, C=LV");
		audienceUris.add(new URI("https://pakalpojumi.carnikava.lv/prod"));
		entityId = "http://www.latvija.lv/sts";
		issuer = "http://www.latvija.lv/sts";
		issuerDN = "CN=VISS Root CA, DC=viss, DC=int";
		context = "c6ibufXPEnVbU9hYc6rplyhjtEpWHEKWuMAJ8ryk4f";

	}

	@Before
	public void setUp() {

		// validator prefilling with common test settings
		validator.setSubjectDNs(subjectDNs);
		validator.setAudienceUris(audienceUris);
		validator.setEntityId(entityId);
		validator.setIssuerDN(issuerDN);
		validator.setIssuer(issuer);
		validator.setContext(context);
		validator.setValidateExpiration(false);
		validator.setMaxClockSkew(maxClockSkew);
		testFile = new File("testToken.xml");
		validator.setCertificate(null);
		validator.setSTSErrorCollector(errorCollector);

		try {
			testToken = FileUtils.readFileToString(testFile);
		} catch (IOException e) {
			// TODO Auto-generated catch block
		}
	}
	
	@After 
	public void tearDown() {
		log.info(validator.errorCollector.listErrors());
}

	@Test
	public void testNegBadSignature() throws Exception {
		// Current settings
		File tamperedFile = new File("tamperedToken.xml");
		testToken = FileUtils.readFileToString(tamperedFile);
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegBadSignature failed");

		} catch (Exception e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals("Invalid signature", e.getMessage());
			log.info("testNegBadSignature passed");
		} finally {
			// Renew default settings
			testFile = new File("testToken.xml");
			testToken = FileUtils.readFileToString(tamperedFile);
		}
	}

	@Test
	public void testNegWrongSubjectDNs() throws Exception {
		// Current settings
		List<String> wrongIssuers = new ArrayList<String>();
		wrongIssuers.add("Wrong Issuer");
		validator.setSubjectDNs(wrongIssuers);
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegWrongSubjectDNs failed");
		} catch (STSException e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals("Wrong token SubjectDN", e.getMessage());
			log.info("testNegWrongSubjectDNs passed");
		} finally {
			validator.setSubjectDNs(subjectDNs);
		}
	}

	@Test
	public void testNegWrongAudience() throws Exception {
		// Current settings
		List<URI> wrongAudienceUris = new ArrayList<URI>();
		wrongAudienceUris.add(new URI("http://Wrong/Audience"));
		validator.setAudienceUris(wrongAudienceUris);
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegWrongAudience failed");
		} catch (STSException e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals("The token applies to an untrusted audience: "
					+ audienceUris.get(0), e.getMessage());
			log.info("testNegWrongAudience passed");
		} finally {
			validator.setAudienceUris(audienceUris);
		}
	}

	@Test
	public void testNegWrongEntityId() throws Exception {
		// Current settings
		validator.setEntityId("WrongEntityId");
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegWrongEntityId failed");
		} catch (STSException e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals("Invalid signature", e.getMessage());
			log.info("testNegWrongEntityId passed");
		} finally {
			validator.setEntityId(entityId);
		}
	}

	@Test
	public void testNegWrongIssuerDN() throws Exception {
		// Current settings
		validator.setIssuerDN("WrongIssuerDN");
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegWrongIssuerDN failed");
		} catch (STSException e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals("Wrong token IssuerDN", e.getMessage());
			log.info("testNegWrongIssuerDN passed");
		} finally {
			validator.setIssuerDN(issuerDN);
		}
	}

	@Test
	public void testNegWrongDate() throws Exception {
		// Current settings
		validator.setValidateExpiration(true);
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegWrongDate failed");
		} catch (STSException e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals(
					"Token Created or Expires elements have been expired",
					e.getMessage());
			log.info("testNegWrongDate passed");
		} finally {
			validator.setValidateExpiration(false);
		}
	}

	@Test
	public void testNegWrongContext() throws Exception {
		// Current settings
		validator.setContext("WrongContext");
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegWrongContext failed");
		} catch (STSException e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals(
					"Wrong token Context. Suspected: WrongContext got: "
							+ context, e.getMessage());
			log.info("testNegWrongContext passed");
		} finally {
			validator.setContext(context);
		}
	}

	@Test
	public void testNegWrongIssuer() throws Exception {
		// Current settings
		validator.setIssuer("WrongIssuer");
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegWrongIssuer failed");
		} catch (STSException e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals("Wrong token Issuer", e.getMessage());
			log.info("testNegWrongIssuer passed");
		} finally {
			validator.setIssuer(issuer);
		}
	}

	@Test
	public void testPosValidationUsingMetadata() throws Exception {
		// Validate token
		List<STSClaim> claims = validator.validate(testToken);
		log.info("Validation passed. Claims: " + claims.size());
		for (int i = 0; i < claims.size(); i++) {
			log.debug("claim " + claims.get(i).getClaimType() + ' '
					+ claims.get(i).getClaimValues());
		}
		log.info("testPosValidationUsingMetadata passed");
	}

	@Test
	public void testPosValidationUsingCertificate() throws Exception {

		validator.setCertificate(getCert("VISS.LVP.STS.cer"));
		// Validate token
		List<STSClaim> claims = validator.validate(testToken);
		log.info("Validation passed. Claims: " + claims.size());
		for (int i = 0; i < claims.size(); i++) {
			log.debug("claim " + claims.get(i).getClaimType() + ' '
					+ claims.get(i).getClaimValues());
		}
		log.info("testPosValidationUsingCertificate passed");
	}

	@Test(expected = STSException.class)
	public void testNegValidationUsingWrongCertificate() throws Exception {

		validator.setCertificate(getCert("VISS.LVP.STS.wrong.cer"));
		// Validate token
		validator.validate(testToken);
	}
	
	@Test
	public void testNegBadToken() throws Exception {
		// Current settings
		validator.errorCollector.clearErrorList();
		File tamperedFile = new File("tamperedToken1.xml");
		testToken = FileUtils.readFileToString(tamperedFile);
		// Validate token
		List<STSClaim> claims = null;
		try {
			claims = validator.validate(testToken);
			log.error("testNegBadSignature failed");
			log.error(validator.errorCollector.listErrors());
		} catch (Exception e) {
			Assert.assertEquals(claims, null);
			Assert.assertEquals("Invalid signature", e.getMessage());
			log.info("testNegBadSignature passed");
		} finally {
			// Renew default settings
			testFile = new File("testToken.xml");
			testToken = FileUtils.readFileToString(tamperedFile);
		}
	}


	private X509Certificate getCert(String filename)
			throws FileNotFoundException, CertificateException {

		FileInputStream fr;
		X509Certificate cer = null;
		fr = new FileInputStream(filename);
		CertificateFactory cf;
		cf = CertificateFactory.getInstance("X509");
		cer = (X509Certificate) cf.generateCertificate(fr);
		return cer;
	}

}
