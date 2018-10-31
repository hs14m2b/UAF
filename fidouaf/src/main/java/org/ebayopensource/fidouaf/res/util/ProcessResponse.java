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

package org.ebayopensource.fidouaf.res.util;

import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.ops.AuthenticationResponseProcessing;
import org.ebayopensource.fido.uaf.ops.RegistrationResponseProcessing;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;

public class ProcessResponse {

	private static int SERVER_DATA_EXPIRY_IN_MS = 5 * 60 * 1000;

	private Notary _notary = null;
	private StorageInterface _storage = null;
	
	// Gson gson = new Gson ();

	public ProcessResponse(Notary notary, StorageInterface storage, int data_expiry)
	{
		this._notary = notary;
		this._storage = storage;
		SERVER_DATA_EXPIRY_IN_MS = data_expiry;
	}
	
	public ProcessResponse() {
		this._notary = NotaryImpl.getInstance();
		this._storage = StorageImpl.getInstance();
	}
	public AuthenticatorRecord[] processAuthResponse(AuthenticationResponse resp) {
		AuthenticatorRecord[] result = null;
		try {
			result = new AuthenticationResponseProcessing(
					SERVER_DATA_EXPIRY_IN_MS, _notary).verify(
					resp, _storage);
		} catch (Exception e) {
			System.out
					.println("!!!!!!!!!!!!!!!!!!!..............................."
							+ e.getMessage());
			result = new AuthenticatorRecord[1];
			result[0] = new AuthenticatorRecord();
			result[0].status = e.getMessage();
		}
		return result;
	}

	public RegistrationRecord[] processRegResponse(RegistrationResponse resp) {
		RegistrationRecord[] result = null;
		try {
			result = new RegistrationResponseProcessing(
					SERVER_DATA_EXPIRY_IN_MS, _notary)
					.processResponse(resp);
		} catch (Exception e) {
			System.out
					.println("!!!!!!!!!!!!!!!!!!!..............................."
							+ e.getMessage());
			result = new RegistrationRecord[1];
			result[0] = new RegistrationRecord();
			result[0].status = e.getMessage();
		}
		return result;
	}
}