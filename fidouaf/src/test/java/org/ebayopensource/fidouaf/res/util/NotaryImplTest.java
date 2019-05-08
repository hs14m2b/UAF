package org.ebayopensource.fidouaf.res.util;

import static org.junit.Assert.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

public class NotaryImplTest {
    private static final Logger logger = LogManager.getLogger(NotaryImplTest.class);

	@Before
	public void before()
	{
		int SERVER_DATA_EXPIRY_IN_MS = Integer.parseInt(System.getenv("FIDO_EXPIRY_MSECS"));
		String DDB_REGION = System.getenv("DDB_REGION");
		String secretName = System.getenv("SECRET_KEY_NAME");   //"test/HMACNotarySecret";
		String SIGNATURES_TABLE_NAME = System.getenv("SIGNATURES_TABLE_NAME");   //"test/HMACNotarySecret";
		logger.debug(DDB_REGION);
		logger.debug(secretName);
		logger.debug(SIGNATURES_TABLE_NAME);
		logger.debug(SERVER_DATA_EXPIRY_IN_MS+"");
	}

	@Test
	public void basic() {
		assertNotNull(NotaryImpl.getInstance());
	}
}
