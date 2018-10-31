package org.ebayopensource.fidouaf.res.util;

import static org.junit.Assert.*;

import org.junit.Test;

public class NotaryImplTest {

	@Test
	public void basic() {
		assertNotNull(NotaryImpl.getInstance());
	}
}
