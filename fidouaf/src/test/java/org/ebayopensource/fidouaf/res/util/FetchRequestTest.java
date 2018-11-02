package org.ebayopensource.fidouaf.res.util;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fidouaf.stats.Dash;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.google.gson.Gson;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FetchRequestTest {

    private static final Logger logger = LogManager.getLogger(FetchRequestTest.class);
	private Notary notary = NotaryImplStub.getInstance();
	Gson gson = new Gson ();
	@Test
	public void test_a() {
		logger.info("Starting basic test");
		FetchRequest _fr = new FetchRequest(TestUtils.getAppId(), TestUtils.getAllowedAaids() ,notary);
		assertNotNull(_fr); 
		logger.info("Completed basic test");
	}
	
	@Test
	public void test_b() {
		logger.info("Starting getAuthenticationRequest test");
		FetchRequest _fr = new FetchRequest(TestUtils.getAppId(), TestUtils.getAllowedAaids() ,notary);
		AuthenticationRequest _ar = _fr.getAuthenticationRequest();
		String _ars = gson.toJson(_ar, org.ebayopensource.fido.uaf.msg.AuthenticationRequest.class);
		logger.info(_ars);
		assertNotNull(_ar.challenge);
		logger.info("Completed getAuthenticationRequest test");
	}

	@Test
	public void test_c() {
		logger.info("Starting getRegistrationRequest test");
		FetchRequest _fr = new FetchRequest(TestUtils.getAppId(), TestUtils.getAllowedAaids() ,notary);
		RegistrationRequest regRequest = _fr.getRegistrationRequest(TestUtils.getUserName());
		logger.info(regRequest.challenge);
		logger.info(regRequest.username);
		assertTrue(regRequest.username.equals(TestUtils.getUserName()));
		logger.info("Completed getRegistrationRequest test");
	}
	

}
