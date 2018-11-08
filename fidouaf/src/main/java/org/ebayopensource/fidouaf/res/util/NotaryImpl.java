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
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DeleteItemOutcome;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.PutItemSpec;

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
	private static int SERVER_DATA_EXPIRY_IN_MS = Integer.parseInt(System.getenv("FIDO_EXPIRY_MSECS"));
	private String DDB_REGION;
	private AmazonDynamoDB ddb;
	private DynamoDB dynamoDB;
	private Table signaturesTable;
	//private String hmacSecret = "HMAC-is-just-one-way";
	private static Notary instance = new NotaryImpl();
	private SecretHelper secretHelper = null;
	private String secretName;   //"test/HMACNotarySecret";
	private String SIGNATURES_TABLE_NAME;

	private NotaryImpl() {
		// Init
		try {
			logger.trace("Initialising NotaryImpl");
			DDB_REGION = System.getenv("DDB_REGION");
			secretName = System.getenv("SECRET_KEY_NAME");
			SIGNATURES_TABLE_NAME = System.getenv("SIGNATURES_TABLE_NAME");
			secretHelper =  SecretHelper.getInstance();
			logger.trace("Created secretHelper");
			logger.trace("Secret Name within secrets manager is " + secretName);
			ddb = AmazonDynamoDBClient.builder().withRegion(DDB_REGION).build();
			dynamoDB = new DynamoDB(ddb);
			signaturesTable = dynamoDB.getTable(SIGNATURES_TABLE_NAME);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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
			String signature = Base64.encodeBase64URLSafeString(HMAC.sign(signData, secretHelper.getCurrent(secretName)));
			storeAWS(signature);
			return signature;
		} catch (Exception e) {
			logger.error(e.toString());
		}
		return null;
	}

	public boolean verify(String signData, String signature) {
		logger.trace("Entered verify of NotaryImpl");
		if (!verifyAWS(signature))
		{
			logger.warn("The signature failed the replay check");
			return false;
		}
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

	private void storeAWS(String signature)
	{
		logger.trace("Entered storeAWS to store ... " + signature);
		//signaturessTable
		Item signatureItem = new Item()
				.withPrimaryKey("signature", signature)
				.withNumber("expires", ((System.currentTimeMillis() + SERVER_DATA_EXPIRY_IN_MS)/ 1000L));
		PutItemSpec putSpec = new PutItemSpec().withItem(signatureItem);
		signaturesTable.putItem(putSpec);
		logger.trace("Successfully stored item in DDB ... ");
	}

	private boolean verifyAWS(String signature)
	{
		logger.trace("Entered verifyAWS to check signature ... " + signature);
		GetItemSpec spec = new GetItemSpec().withPrimaryKey("signature", signature);
        try {
        	logger.trace("Attempting to read the item with key... " + signature);
        	//logger.log("Attempting to read the item...");
            Item outcome = signaturesTable.getItem(spec);
            if (outcome == null)
            {
            	logger.trace("Item was not present - return false");
            	return false;
            }
            else
            {
            	logger.trace("GetItem succeeded: " + outcome.toJSONPretty());
            	logger.trace("Deleting item to prevent replay attacks");
        		DeleteItemSpec delSpec = new DeleteItemSpec().withPrimaryKey("signature", signature);
                try {
                	logger.trace("Attempting to delete the signature...");
                    DeleteItemOutcome delOutcome = signaturesTable.deleteItem(delSpec);
                    logger.trace("Deleted signature from DynamoDB");
                    logger.trace(delOutcome.getDeleteItemResult().toString());
            		return true;
                }
                catch (Exception dex) {
                    logger.error("DeleteItem failed: " + dex.getMessage());
                    return false;
                }
            }
        }
        catch (Exception e) {
            logger.error("GetItem failed: " + e.getMessage());
        	return false;
        }
	}

}
