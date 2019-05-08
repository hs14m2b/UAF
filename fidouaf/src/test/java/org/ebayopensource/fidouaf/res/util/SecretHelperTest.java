package org.ebayopensource.fidouaf.res.util;

import static org.junit.Assert.*;

import org.junit.Test;

public class SecretHelperTest {

	@Test
	public void basic() {
		assertNotNull(SecretHelper.getInstance());
	}
}
