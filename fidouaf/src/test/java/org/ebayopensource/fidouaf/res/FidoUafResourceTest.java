package org.ebayopensource.fidouaf.res;

import static org.junit.Assert.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.ebayopensource.fidouaf.res.util.FetchRequest;
import org.ebayopensource.fidouaf.res.util.FetchRequestTest;
import org.ebayopensource.fidouaf.res.util.NotaryImplStub;
import org.ebayopensource.fidouaf.res.util.StorageImplStub;
import org.ebayopensource.fidouaf.res.util.TestUtils;
import org.ebayopensource.stub.fido.uaf.client.AuthenticationRequestProcessor;
import org.ebayopensource.stub.fido.uaf.client.RegistrationRequestProcessor;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.google.gson.Gson;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FidoUafResourceTest {

	private final StorageInterface storage = StorageImplStub.getInstance();
	private final Notary notary = NotaryImplStub.getInstance();
	private final Gson gson = new Gson();
    private static final Logger logger = LogManager.getLogger(FidoUafResourceTest.class);
	private KeyPair kp = null;

	
	@Before
	public void before() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
	{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDsA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec, new SecureRandom());
        kp = keyGen.generateKeyPair();
	}

	@Test
	public void test_a() {
		assertNotNull(new FidoUafResource(storage, notary));
	}
	@Test
	public void test_b() {
		logger.info("Starting getRegistrationRequest test");
		FidoUafResource far = new FidoUafResource(storage, notary);
		RegistrationRequest[] rr_response = far.getRegisReqPublic(TestUtils.getUserName());
		assertTrue(rr_response.length==1);
		String rr_responses = gson.toJson(rr_response[0], RegistrationRequest.class);
		logger.info(rr_responses);
		assertTrue(rr_response[0].username.equalsIgnoreCase(TestUtils.getUserName()));
		assertNotNull(rr_response[0].challenge);
		assertNotNull(rr_response[0].header);
		assertNotNull(rr_response[0].policy);
		logger.info("Completed getRegistrationRequest test");
	}
	@Test
	public void test_c() {
		logger.info("Starting Registration response test");
		FidoUafResource far = new FidoUafResource(storage, notary);
		RegistrationRequest[] rr_response = far.getRegisReqPublic(TestUtils.getUserName());
		assertTrue(rr_response.length==1);
		String rr_responses = gson.toJson(rr_response[0], RegistrationRequest.class);
		RegistrationRequest _rrstub = gson.fromJson(rr_responses,RegistrationRequest.class);
		logger.info("Successfully cast Regitraton Request into Stub object");
		logger.info(rr_responses);
		assertTrue(rr_response[0].username.equalsIgnoreCase(TestUtils.getUserName()));
		assertNotNull(rr_response[0].challenge);
		assertNotNull(rr_response[0].header);
		assertNotNull(rr_response[0].policy);
		logger.info("Got successful registration request - passing to fido client stub");
		RegistrationRequestProcessor _rrp = new RegistrationRequestProcessor();
		RegistrationResponse _rrspstub =  _rrp.processRequest(_rrstub, kp);
		logger.info("Got successful registration response from fido client stub");
		String _rrsps = gson.toJson(_rrspstub, RegistrationResponse.class);
		_rrsps = "[" + _rrsps + "]";
		RegistrationResponse[] _rrsp = gson.fromJson(_rrsps, RegistrationResponse[].class);
		assertTrue(_rrsp[0].assertions.length > 0);
		logger.info("Successfully cast response into real RegistrationResponse array object");
		logger.info(_rrsp[0].assertions[0].assertion);
		logger.info(_rrsp[0].assertions[0].assertionScheme);
		RegistrationRecord[] _rrec = far.processRegResponse(_rrsps);
		assertNotNull(_rrec[0]);
		assertTrue(_rrec[0].status.equalsIgnoreCase("SUCCESS"));
		logger.info(_rrec[0].status);
		logger.info("Completed process registration response test");
	}

	@Test
	public void test_d() {
		logger.info("Starting Registration response test");
		FidoUafResource far = new FidoUafResource(storage, notary);
		RegistrationRequest[] rr_response = far.getRegisReqPublic(TestUtils.getUserName());
		assertTrue(rr_response.length==1);
		String rr_responses = gson.toJson(rr_response[0], RegistrationRequest.class);
		RegistrationRequest _rrstub = gson.fromJson(rr_responses,RegistrationRequest.class);
		logger.info("Successfully cast Regitraton Request into Stub object");
		logger.info(rr_responses);
		assertTrue(rr_response[0].username.equalsIgnoreCase(TestUtils.getUserName()));
		assertNotNull(rr_response[0].challenge);
		assertNotNull(rr_response[0].header);
		assertNotNull(rr_response[0].policy);
		logger.info("Got successful registration request - passing to fido client stub");
		RegistrationRequestProcessor _rrp = new RegistrationRequestProcessor();
		RegistrationResponse _rrspstub =  _rrp.processRequest(_rrstub, kp);
		logger.info("Got successful registration response from fido client stub");
		String _rrsps = gson.toJson(_rrspstub, RegistrationResponse.class);
		_rrsps = "[" + _rrsps + "]";
		RegistrationResponse[] _rrsp = gson.fromJson(_rrsps, RegistrationResponse[].class);
		assertTrue(_rrsp[0].assertions.length > 0);
		logger.info("Successfully cast response into real RegistrationResponse array object");
		logger.info(_rrsp[0].assertions[0].assertion);
		logger.info(_rrsp[0].assertions[0].assertionScheme);
		RegistrationRecord[] _rrec = far.processRegResponse(_rrsps);
		assertNotNull(_rrec[0]);
		assertTrue(_rrec[0].status.equalsIgnoreCase("SUCCESS"));
		logger.info(_rrec[0].status);
		logger.info("Completed process registration response test");
		logger.info("Starting Authentication response test");
		String _ars = far.getAuthReq();
		logger.info("Got an authentication request");
		assertFalse(_ars.equals(""));
		AuthenticationRequest[] _arstub = gson.fromJson(_ars,AuthenticationRequest[].class);
		logger.info("Cast authentication request message into stub object");
		org.ebayopensource.stub.fido.uaf.crypto.FidoSigner _fs = new org.ebayopensource.stub.fido.uaf.crypto.FidoSignerBC();
		AuthenticationRequestProcessor _arp = new AuthenticationRequestProcessor(_fs, kp);
		logger.info("Created stub authentication request processor object");
		assertNotNull(_arp); 
		AuthenticationResponse _arspstub =  _arp.processRequest(_arstub[0]);
		logger.info("Obtained authentication response stub object");
		assertTrue(_arspstub.assertions.length > 0);
		logger.info(_arspstub.assertions[0].assertion);
		logger.info(_arspstub.assertions[0].assertionScheme);
		String _arsps =gson.toJson(_arspstub, AuthenticationResponse.class); 
		_arsps = "[" + _arsps + "]";
		logger.info(_arsps);
		AuthenticatorRecord[] _arec = far.processAuthResponse(_arsps);
		assertNotNull(_arec[0]);
		assertTrue(_arec[0].status.equalsIgnoreCase("SUCCESS"));
		assertTrue(_arec[0].username.equals(TestUtils.getUserName()));
		String _arecs =gson.toJson(_arec, AuthenticatorRecord[].class); 
		logger.info(_arecs);
		logger.info("Completed Authentication response test");
	}

}
