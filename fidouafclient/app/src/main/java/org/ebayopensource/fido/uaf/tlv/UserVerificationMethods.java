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

package org.ebayopensource.fido.uaf.tlv;

public enum UserVerificationMethods {

	USER_VERIFY_PRESENCE (1),
	USER_VERIFY_FINGERPRINT (2),
	USER_VERIFY_PASSCODE (4),
	USER_VERIFY_VOICEPRINT (8),
	USER_VERIFY_FACEPRINT (16),
	USER_VERIFY_LOCATION (32),
	USER_VERIFY_EYEPRINT (64),
	USER_VERIFY_PATTERN (128),
	USER_VERIFY_HANDPRINT (256),
	USER_VERIFY_NONE (512),
	USER_VERIFY_ALL (1024);

	public final int id;

	UserVerificationMethods(int id){
		this.id = id;
	}
}
