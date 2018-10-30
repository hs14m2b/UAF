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
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.crypto.HMAC;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.MessageDigest;


/**
 * This is just an example implementation. You should implement this class based on your operational environment.
 */
public class NotaryImpl implements Notary {

    private static final Logger logger = LogManager.getLogger(NotaryImpl.class);
	//private String hmacSecret = "HMAC-is-just-one-way";
	private static Notary instance = new NotaryImpl();
	private SecretHelper secretHelper = null;
	private static String secretName = System.getenv("SECRET_KEY_NAME");   //"test/HMACNotarySecret";

	private NotaryImpl() {
		// Init
		logger.trace("Initialising NotaryImpl");
		secretHelper =  SecretHelper.getInstance();
		logger.trace("Created secretHelper");
		logger.trace("Secret Name within secrets manager is " + secretName);

	}

	public static Notary getInstance() {
		return instance;
	}

	public void rotateSecret()
	{
		logger.trace("Entered rotateSecret");
		secretHelper.updateSecrets(secretName);
		logger.trace("Exiting rotateSecret - secret values have been updated from Secrets Manager");
	}
	
	public String sign(String signData) {
		try {
			return Base64.encodeBase64URLSafeString(HMAC.sign(signData, secretHelper.getCurrent(secretName)));
		} catch (Exception e) {
			logger.error(e.toString());
		}
		return null;
	}

	public boolean verify(String signData, String signature) {
		logger.trace("Entered verify of NotaryImpl");
		try {
			boolean result = false;
			result = MessageDigest.isEqual(Base64.decodeBase64(signature), HMAC.sign(signData, secretHelper.getCurrent(secretName)));
			if (!result)
			{
				logger.warn("Verification of signature failed using current secret - trying previous version");
				//try the previous version of the secret
				result = MessageDigest.isEqual(Base64.decodeBase64(signature), HMAC.sign(signData, secretHelper.getPrevious(secretName)));
				if (!result)
				{
					logger.warn("Verification of signature failed using previous secret - updating secrets in case they have been rotated");
					//signatures do not match on current and previous. Check that secrets have not been rotated and check current again
					rotateSecret();
					result = MessageDigest.isEqual(Base64.decodeBase64(signature), HMAC.sign(signData, secretHelper.getCurrent(secretName)));
				}
			}
			logger.trace("Result if signature verification is " + result);
			return result;
		} catch (Exception e) {
			logger.error(e.toString());
		}
		return false;
	}

}
