package org.ebayopensource.fidouaf.res.util;

import static org.junit.Assert.*;

import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@FixMethodOrder(MethodSorters.JVM)
public class FetchRequestTest {

    private static final Logger logger = LogManager.getLogger(FetchRequestTest.class);
	private Notary notary = NotaryImplStub.getInstance();
	@Test
	public void test_a() {
		logger.info("Starting basic test");
		FetchRequest _fr = new FetchRequest(notary);
		assertNotNull(_fr); 
		logger.info("Completed basic test");
	}
	
	@Test
	public void test_b() {
		logger.info("Starting getAuthenticationRequest test");
		FetchRequest _fr = new FetchRequest(notary);
		String authRequestChallenge = _fr.getAuthenticationRequest().challenge;
		logger.info(authRequestChallenge);
		assertNotNull(authRequestChallenge);
		logger.info("Completed getAuthenticationRequest test");
	}

	@Test
	public void test_c() {
		logger.info("Starting getRegistrationRequest test");
		FetchRequest _fr = new FetchRequest(notary);
		String userName = "TESTUSER";
		RegistrationRequest regRequest = _fr.getRegistrationRequest(userName);
		logger.info(regRequest.challenge);
		logger.info(regRequest.username);
		assertTrue(regRequest.username.equals(userName));
		logger.info("Completed getRegistrationRequest test");
	}
}
