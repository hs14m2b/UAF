package org.ebayopensource.fidouaf.res.util;

import static org.junit.Assert.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.ebayopensource.stub.fido.uaf.client.AuthenticationRequestProcessor;
import org.ebayopensource.stub.fido.uaf.client.RegistrationRequestProcessor;
import org.ebayopensource.stub.fido.uaf.crypto.FidoSigner;
import org.ebayopensource.stub.fido.uaf.crypto.FidoSignerBC;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.google.gson.Gson;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ProcessResponseTest {

    private static final Logger logger = LogManager.getLogger(ProcessResponseTest.class);
	private Notary notary = NotaryImplStub.getInstance();
	private StorageInterface storage = StorageImplStub.getInstance();
	private KeyPair kp = null;
	Gson gson = new Gson ();

	@Test
	public void test_a() {
		logger.info("Starting basic test");
		ProcessResponse _pr = new ProcessResponse(notary, storage, Integer.MAX_VALUE);
		assertNotNull(_pr); 
		logger.info("Completed basic test");
	}
	
	//commented this test out for the moment as parallel execution causes problems!
	//this test is invoked from test_c in any case
	//@Test
	public void test_b() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		logger.info("Starting process registration response test");
		FetchRequest _fr = new FetchRequest(TestUtils.getAppId(), TestUtils.getAllowedAaids() ,notary);
		RegistrationRequest _rr = _fr.getRegistrationRequest(TestUtils.getUserName());
		String _rrs = gson.toJson(_rr, RegistrationRequest.class);
		RegistrationRequest _rrstub = gson.fromJson(_rrs,RegistrationRequest.class);
		ProcessResponse _pr = new ProcessResponse(notary, storage, 5*60*1000);
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDsA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec, new SecureRandom());
        kp = keyGen.generateKeyPair();
		RegistrationRequestProcessor _rrp = new RegistrationRequestProcessor();
		RegistrationResponse _rrspstub =  _rrp.processRequest(_rrstub, kp);
		String _rrsps = gson.toJson(_rrspstub, org.ebayopensource.stub.fido.uaf.msg.RegistrationResponse.class);
		RegistrationResponse _rrsp = gson.fromJson(_rrsps, RegistrationResponse.class);
		assertTrue(_rrsp.assertions.length > 0);
		logger.info(_rrsp.assertions[0].assertion);
		logger.info(_rrsp.assertions[0].assertionScheme);
		//RegistrationResponse _rrsp = getResponse();
		RegistrationRecord[] _rrec = _pr.processRegResponse(_rrsp);
		try
		{
			storage.store(_rrec);
			logger.info("Stored registration record");
			logger.info(gson.toJson(_rrec[0], RegistrationRecord.class));
		}
		catch (Exception ex)
		{
			logger.error("Failed to store registration record" + ex.getMessage());
		}
		assertNotNull(_rrec[0]);
		assertTrue(_rrec[0].status.equalsIgnoreCase("SUCCESS"));
		logger.info(_rrec[0].status);
		logger.info("Completed process registration response test");
	}

	@Test
	public void test_c() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		logger.info("Starting process authentication response test");
		if (kp == null)
		{
			logger.info("Key Pair is null so running test b to generate and register a key");
			test_b();
		}
		FetchRequest _fr = new FetchRequest(TestUtils.getAppId(), TestUtils.getAllowedAaids() ,notary);
		AuthenticationRequest _ar = _fr.getAuthenticationRequest();
		logger.info("Obtained an authentication request message");
		String _ars = gson.toJson(_ar, AuthenticationRequest.class);
		logger.info(_ars);
		AuthenticationRequest _arstub = gson.fromJson(_ars,AuthenticationRequest.class);
		logger.info("Cast authentication request message into stub object");
		org.ebayopensource.stub.fido.uaf.crypto.FidoSigner _fs = new org.ebayopensource.stub.fido.uaf.crypto.FidoSignerBC();
		AuthenticationRequestProcessor _arp = new AuthenticationRequestProcessor(_fs, kp);
		logger.info("Created stub authentication request processor object");
		assertNotNull(_arp); 
		AuthenticationResponse _arspstub =  _arp.processRequest(_arstub);
		logger.info("Obtained authentication response stub object");
		assertTrue(_arspstub.assertions.length > 0);
		logger.info(_arspstub.assertions[0].assertion);
		logger.info(_arspstub.assertions[0].assertionScheme);
		String _arsps =gson.toJson(_arspstub, AuthenticationResponse.class); 
		logger.info(_arsps);
		AuthenticationResponse _arsp = gson.fromJson(_arsps,AuthenticationResponse.class);
		logger.info("Created real authentication response object from stringified stub object");
		ProcessResponse _pr = new ProcessResponse(notary, storage, 5*60*1000);
		logger.info("Processing authentication response - expecting SUCCESS");
		AuthenticatorRecord[] _arec = _pr.processAuthResponse(_arsp);
		assertNotNull(_arec[0]);
		assertTrue(_arec[0].status.equalsIgnoreCase("SUCCESS"));
		logger.info(_arec[0].status);
		logger.info("Recreating response processing object with timeout of 1 ms");
		logger.info("Processing authentication response - expecting FAILURE due to timeout");
		_pr = new ProcessResponse(notary, storage, 1);
		_arec = _pr.processAuthResponse(_arsp);
		assertNotNull(_arec[0]);
		assertFalse(_arec[0].status.equalsIgnoreCase("SUCCESS"));
		logger.info(_arec[0].status);
		logger.info("Completed process authentication response test");
	}

	
	private RegistrationResponse getResponse() {
		return gson.fromJson(getTestRegResponse(), RegistrationResponse.class);
	}

	private String getTestRegResponse()
	{
		return "{\"assertions\":[{\"assertion\":\"AT4lAwM-2AALLgkARUJBMCMwMDAxDi4HAAAAAQEAAAEKLiAAandVDoBlh_f979Rc3zKxKw7PfQgUgcvMPrz7AJ7fDQAJLkcAWldKaGVTMTBaWE4wTFd0bGVTMUtSRXBvU2tSRmQwcEhjRWxaVjJSb1QxUldkV1JJUWtSbFJXdzBXVzVPZEZKWVdrOVBSVGcNLggAAAABAAAAAQAMLkEABKuxyJrpJBm1Rj6h9lBy-1CdvMzR1r8Ug0HlrDnfQcQOQAzXu2lU0VRiamSJWFLraldDUkLaEq5x54nLAgqqUQoHPkUCBi5AAMdmFmSuPI0v7cK9ZJRKgtwQ8ETQejz8NkHgymX8ENKzJOZiKtHECu9ga4MvA2aXTo0pL243OI-Hp6sZvEXrqFMFLv0BMIIB-TCCAZ-gAwIBAgIEVTFM0zAJBgcqhkjOPQQBMIGEMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCFNhbiBKb3NlMRMwEQYDVQQKDAplQmF5LCBJbmMuMQwwCgYDVQQLDANUTlMxEjAQBgNVBAMMCWVCYXksIEluYzEeMBwGCSqGSIb3DQEJARYPbnBlc2ljQGViYXkuY29tMB4XDTE1MDQxNzE4MTEzMVoXDTE1MDQyNzE4MTEzMVowgYQxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UEBwwIU2FuIEpvc2UxEzARBgNVBAoMCmVCYXksIEluYy4xDDAKBgNVBAsMA1ROUzESMBAGA1UEAwwJZUJheSwgSW5jMR4wHAYJKoZIhvcNAQkBFg9ucGVzaWNAZWJheS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ8hw5lHTUXvZ3SzY9argbOOBD2pn5zAM4mbShwQyCL5bRskTL3HVPWPQxqYVM-3pJtJILYqOWsIMd5Rb_h8D-EMAkGByqGSM49BAEDSQAwRgIhAIpkop_L3fOtm79Q2lKrKxea-KcvA1g6qkzaj42VD2hgAiEArtPpTEADIWz2yrl5XGfJVcfcFmvpMAuMKvuE1J73jp4\",\"assertionScheme\":\"UAFV1TLV\"}],\"fcParams\":\"eyJhcHBJRCI6Imh0dHBzOi8vYXBpLm1yLWIuY2xpY2svZmlkby9maWRvdWFmL3YxL3B1YmxpYy91YWYvZmFjZXRzIiwiY2hhbGxlbmdlIjoiSkRKaEpERXdKRzVuVTJkRWRIaGhTWGxaVGtreVZURkxieTVVUkU4IiwiZmFjZXRJRCI6IiJ9\",\"header\":{\"appID\":\"https://api.mr-b.click/fido/fidouaf/v1/public/uaf/facets\",\"op\":\"Reg\",\"serverData\":\"cm9iS2wtdW0zN0tFQWFkU2hmSTh5RXlQX3RDZ0g3UGFkSk1RZVVlSHd5NC5NVFUwTURrNU1EZ3dPVGt3T0EuTmpZMU5EazJPREl0T0dGaU1TMDBaR014TFRnMU1qUXROelExWTJZM09XTmxOR1UwLlNrUkthRXBFUlhkS1J6VnVWVEprUldSSWFHaFRXR3hhVkd0cmVWWlVSa3hpZVRWVlVrVTQ\",\"upv\":{\"major\":1,\"minor\":0}}}";
	}

	private AuthenticationResponse getAuthResponse() {
		return gson.fromJson(getTestAuthResponse(), AuthenticationResponse.class);
	}

	private String getTestAuthResponse()
	{
		return "{ \"assertions\": [ { \"assertion\": \"Aj4kAQQ-1QALLgkARUJBMCMwMDAxDi4FAAAAAQIADy5AADM0ZDI2M2I0OTdjM2FlYzM4OTc1N2NmZGFjZTFkMDY1NGM4OTNlMzBmNzFlMTk4ZmRmZTYxODQxZjlhNWNlYzEKLiAAUt9c99-BUfuk4lKtrbVFbv8uEm0swo2Vx0sDa5UBXVAQLgAACS5HAFpXSmhlUzEwWlhOMExXdGxlUzFLUkVwb1NrUkZkMHBIY0VsWlYyUm9UMVJXZFdSSVFrUmxSV3cwV1c1T2RGSllXazlQUlRnDS4EAAAAAQAGLkcAMEUCIQCfZG99O92K3F26maZhFgSWMOZ8XU07KLvLFBa2MDBvmQIgCM8VH-C_83b51vXlffcqlpILmmjmQWD3zc1UexAF_TE\", \"assertionScheme\": \"UAFV1TLV\" } ], \"fcParams\": \"eyJhcHBJRCI6Imh0dHBzOi8vYXBpLm1yLWIuY2xpY2svZmlkby9maWRvdWFmL3YxL3B1YmxpYy91YWYvZmFjZXRzIiwiY2hhbGxlbmdlIjoiSkRKaEpERXdKSEZpTTFNME5XOXdlWFZUY2tWMkx6Um5hUzkzYVM0IiwiZmFjZXRJRCI6IiJ9\", \"header\": { \"appID\": \"https://api.mr-b.click/fido/fidouaf/v1/public/uaf/facets\", \"op\": \"Auth\", \"serverData\": \"S3dENklIMExmYjFrOHNaLTJQeC1DMWJmSVI1d05OVC0tWGNnLXNkVWhMWS5NVFUwTURrNU1qWTBPRGN3TncuU2tSS2FFcEVSWGRLU0VacFRURk5NRTVYT1hkbFdGWlVZMnRXTWt4NlVtNWhVemt6WVZNMA\", \"upv\": { \"major\": 1, \"minor\": 0 } }}";
	}

}