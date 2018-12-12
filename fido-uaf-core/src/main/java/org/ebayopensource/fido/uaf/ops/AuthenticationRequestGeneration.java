/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fido.uaf.ops;

import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.crypto.BCrypt;
import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.Extension;
import org.ebayopensource.fido.uaf.msg.MatchCriteria;
import org.ebayopensource.fido.uaf.msg.Operation;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.Policy;
import org.ebayopensource.fido.uaf.msg.Version;

public class AuthenticationRequestGeneration {

	private String appId = RegistrationRequestGeneration.APP_ID;
	private static final String OP_HEADER_EXT_UVM = "fido.uaf.uvm";
	private static final long[] ACCEPTED_USER_VERIFICATIONS = new long[] {1027, 1041, 1281};
	private String[] acceptedAaids = null;

	public AuthenticationRequestGeneration() {
	}

	public AuthenticationRequestGeneration(String appId) {
		this.appId = appId;
	}

	public AuthenticationRequestGeneration(String appId, String[] acceptedAaids) {
		this.appId = appId;
		this.acceptedAaids = acceptedAaids;
	}

	public AuthenticationRequest createAuthenticationRequest(Notary notary) {
		AuthenticationRequest authRequest = new AuthenticationRequest();
		OperationHeader header = new OperationHeader();
		authRequest.challenge = generateChallenge();
		header.serverData = generateServerData(authRequest.challenge, notary);
		authRequest.header = header;
		authRequest.header.op = Operation.Auth;
		authRequest.header.appID = appId;
		authRequest.header.upv = new Version(1, 0);
		Extension ext1 = new Extension();
		ext1.id = OP_HEADER_EXT_UVM;
		ext1.fail_if_unknown = true;
		authRequest.header.exts = new Extension[] {ext1};

		authRequest.policy = constructAuthenticationPolicy();

		return authRequest;
	}

	private String generateChallenge() {
		return Base64.encodeBase64URLSafeString(BCrypt.gensalt().getBytes());
	}

	private String generateServerData(String challenge, Notary notary) {
		String dataToSign = Base64.encodeBase64URLSafeString(("" + System
				.currentTimeMillis()).getBytes())
				+ "."
				+ Base64.encodeBase64URLSafeString(challenge.getBytes());
		String signature = notary.sign(dataToSign);

		return Base64.encodeBase64URLSafeString((signature + "." + dataToSign)
				.getBytes());
	}

	public Policy constructAuthenticationPolicy() {
		if (acceptedAaids == null) {
			return null;
		}
		Policy p = new Policy();
		MatchCriteria[][] accepted = new MatchCriteria[ACCEPTED_USER_VERIFICATIONS.length][1];
		for (int i = 0; i < accepted.length; i++) {
			MatchCriteria[] a = new MatchCriteria[1];
			MatchCriteria matchCriteria = new MatchCriteria();
			matchCriteria.assertionSchemes = new String[] {"UAFV1TLV"};
			matchCriteria.userVerification = ACCEPTED_USER_VERIFICATIONS[i];
			matchCriteria.authenticationAlgorithms = new int[] {1,2,5,6};
			matchCriteria.keyProtection = 15;
			a[0] = matchCriteria;
			accepted[i] = a;
		}
		/*for (int i = 0; i < accepted.length; i++) {
			MatchCriteria[] a = new MatchCriteria[1];
			MatchCriteria matchCriteria = new MatchCriteria();
			matchCriteria.aaid = new String[1];
			matchCriteria.aaid[0] = acceptedAaids[i];
			a[0] = matchCriteria;
			accepted[i] = a;
		}*/
		p.accepted = accepted;
		return p;
	}

}
