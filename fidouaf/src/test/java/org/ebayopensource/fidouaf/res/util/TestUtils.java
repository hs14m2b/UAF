package org.ebayopensource.fidouaf.res.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TestUtils {

	public static String[] getAllowedAaids() {
		String[] ret = { "EBA0#0001", "0015#0001", "0012#0002", "0010#0001",
				"4e4e#0001", "5143#0001", "0011#0701", "0013#0001",
				"0014#0000", "0014#0001", "53EC#C002", "DAB8#8001",
				"DAB8#0011", "DAB8#8011", "5143#0111", "5143#0120",
				"4746#F816", "53EC#3801" };
		List<String> retList = new ArrayList<String>(Arrays.asList(ret));
		//retList.addAll(Dash.getInstance().uuids);
		return retList.toArray(new String[0]);
	}
	
	public static String getAppId()
	{
		return "https://api.mr-b.click/fido/fidouaf/v1/public/uaf/facets";
	}
	
	public static String getUserName()
	{
		return "TESTUSER";
	}

}
