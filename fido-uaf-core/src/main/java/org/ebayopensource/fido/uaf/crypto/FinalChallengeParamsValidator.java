package org.ebayopensource.fido.uaf.crypto;

import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;

public interface FinalChallengeParamsValidator {
	public boolean validate(FinalChallengeParams finalChallengeParams)
			throws Exception;

}
