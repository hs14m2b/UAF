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

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ebayopensource.fido.uaf.storage.DuplicateKeyException;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.ebayopensource.fido.uaf.storage.SystemErrorException;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.amazonaws.services.dynamodbv2.document.DeleteItemOutcome;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.PutItemSpec;


public class StorageImplStub implements StorageInterface {

    private static final Logger logger = LogManager.getLogger(StorageImplStub.class);
	private static StorageImplStub instance = new StorageImplStub();
	private Map<String, RegistrationRecord> db = new HashMap<String, RegistrationRecord>();
	private Map<String, String> db_names = new HashMap<String, String>();

	protected Gson gson = new GsonBuilder().disableHtmlEscaping().create();

	private StorageImplStub() {
		// Init
		try {
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static StorageInterface getInstance() {
		return instance;
	}

	public void storeServerDataString(String username, String serverDataString) {
		logger.info("Entered storeServerDataString with username " + username + " and serverDataString " + serverDataString);
		if (db_names.containsKey(serverDataString)){
			db_names.remove(serverDataString);
		}
		db_names.put(serverDataString, username);
	}

	public String getUsername(String serverDataString) {
		logger.info("Entered getUsername with serverDataString " + serverDataString);
		if (db_names.containsKey(serverDataString)){
			return db_names.get(serverDataString);
		}
		return null;
	}

	public void store(RegistrationRecord[] records)
			throws DuplicateKeyException, SystemErrorException {
		logger.info("Entered store with records length " + records.length);
		if (records != null && records.length > 0) {
			for (int i = 0; i < records.length; i++) {
				if (db.containsKey(records[i].authenticator.toString())) {
					logger.info("Removing record for user  " + records[i].username + " so it can be replaced with new version");
					db.remove(records[i].authenticator.toString());
					logger.info("Removed record for user  " + records[i].username );
				}
				logger.info("Storing record for user  " + records[i].username);
				records[i].authenticator.username = records[i].username;
				logger.info("Record key is  " + records[i].authenticator.toString());
				db.put(records[i].authenticator.toString(), records[i]);
			}
		}
	}
	

	public RegistrationRecord readRegistrationRecord(String key) {
		logger.info("Got request for Registration Record with key " + key);
		RegistrationRecord rr = db.get(key);
		if (rr != null)
		{
			logger.info("Registration Record username details are " + rr.username);
		}
		else
		{
			logger.error("Unable to find record for key  " + key);
		}
		return rr;
	}
	

	public void update(RegistrationRecord[] records) {
		// TODO Auto-generated method stub

	}

	public void deleteRegistrationRecord(String key) {
		if (db != null && db.containsKey(key)) {
			System.out
					.println("!!!!!!!!!!!!!!!!!!!....................deleting object associated with key="
							+ key);
			db.remove(key);
		}
	}

	public Map<String, RegistrationRecord> dbDump() {
		System.out.println("Entered dbDump");
		//TODO - return from DynamoDB
		return db;
	}

}
