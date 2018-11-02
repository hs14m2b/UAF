package org.ebayopensource.fidouaf.res;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.ebayopensource.fidouaf.res.util.NotaryImpl;
import org.ebayopensource.fidouaf.res.util.StorageImpl;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.util.IOUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import java.util.Base64;



public class FidoUafLambdaHandler implements RequestStreamHandler{
	// Initialize the Log4j logger.
	static final Logger logger = LogManager.getLogger(FidoUafLambdaHandler.class);
	protected Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	private final StorageInterface storage = StorageImpl.getInstance();
	private final Notary notary = NotaryImpl.getInstance();
	private final FidoUafResource fidoUafResource;
	//static final String UserTableName = System.getenv("DB_USER_TABLE_NAME");
	//static final String DefaultUser = System.getenv("DEFAULT_USER_IDENTITY"); // b342ff9c-9924-4421-9071-32763f907d9b
	
	JSONParser parser = new JSONParser();

	public FidoUafLambdaHandler(){
		logger.debug("Created FIDO UAF Server Lambda Handler");
		fidoUafResource = new FidoUafResource(storage, notary);
		logger.debug("Created FidoUafResource object with real implementation of notary and storage");
		//logger.debug("Default user is " + DefaultUser);
		//logger.debug("User Table name user is " + UserTableName);
	}

    @SuppressWarnings({ "unchecked", "unused" })
	public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException {
    	//LambdaLogger logger = context.getLogger();
		//This lambda will exercise all the different components utilised by the CID hub to ensure that their health is OK.
		//Returns 200 with output of each check
		//Returns 500 with output of each check if it fails
        //LambdaLogger logger = context.getLogger(); //basic cloudwatch logger
        logger.info("Loading Java Lambda handler of healthcheck");

        JSONObject responseJson = new JSONObject();
        JSONObject responseBody = new JSONObject();
        JSONObject testResults = new JSONObject();
        String responseCode = "200";
		//String user_identifier = DefaultUser;
		String token_cookie = "";
        logger.info("Created response json object for population");

        //BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String strEvent = IOUtils.toString(inputStream);
		logger.info("Successfully read inputStream into String");
		logger.info(strEvent);
        JSONObject event = null;
        try {
            event = (JSONObject)parser.parse(strEvent);
			logger.info("Successfully parsed the input stream to a JSONObject");
			logger.info(event.toJSONString());
            
        } catch(ParseException pex) {
            responseJson.put("statusCode", "400");
            responseJson.put("exception", pex);
			logger.info("Failed to parse the input stream to a JSONObject");
			logger.info(pex.toString());
        }
        
        //check if keep-alive event
        //if (event.containsKey("source") && event.containsKey("detail-type") && event.get("source").toString().equals("aws.events") && event.get("detail-type").toString().equals("Scheduled Event"))
        if (event.containsKey("Records"))
        {
        	logger.info("Received a keep-alive event");
        	logger.info("Updating secret key");
            NotaryImpl.getInstance().rotateSecret();
        	logger.info("Secret key updated");
            OutputStreamWriter writer = new OutputStreamWriter(outputStream, "UTF-8");
            writer.write("{ \"response\" : \"OK\"}");  
            writer.close();
            return;
        }

		final AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.defaultClient();
		String json_body="{}";
		//public/regRequest/{username}
		String pathParameters="";
		if (event.containsKey("pathParameters"))
		{
			pathParameters =((JSONObject)event.get("pathParameters")).get("proxy").toString();
			logger.info("pathParameters are " + pathParameters);
		}
		//switch for different path parameters
		if (pathParameters.startsWith("regRequest/") || pathParameters.equals("regRequest"))
		{
			logger.info("Processing Registration Request");
			//get the username
			//check for Authorization header
			JSONObject headers = (JSONObject)event.get("headers");
			if (headers == null) headers = new JSONObject();
			logger.info("Got Headers object");
			String access_token_jwt = "";
			String username = "";
			if (headers.containsKey("Authorization"))
			{
				logger.info("Authorization key present in headers");
				access_token_jwt = headers.get("Authorization").toString();
				logger.info("Access Token is " + access_token_jwt);
				try {
					JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
			            .setSkipAllValidators()
			            .setDisableRequireSignature()
			            .setSkipSignatureVerification()
			            .build();
					JwtContext jwtContext = firstPassJwtConsumer.process(access_token_jwt);
					username = jwtContext.getJwtClaims().getSubject();
				} catch (InvalidJwtException | MalformedClaimException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					username = pathParameters.substring(11);
				}
			}
			else
			{
				username = pathParameters.substring(11);
			}
			logger.info("Username for registration is " + username);
			RegistrationRequest[] rr_response = fidoUafResource.getRegisReqPublic(username);
			json_body = gson.toJson(rr_response);
		}
		else if (pathParameters.startsWith("regResponse"))
		{
			//client - need to send username with resopnse
			String post_body = event.get("body").toString();
			RegistrationRecord[] rr_response = fidoUafResource.processRegResponse(post_body);
			json_body = gson.toJson(rr_response);
		}
		else if (pathParameters.startsWith("deregRequest"))
		{
			String post_body = event.get("body").toString();
			json_body = fidoUafResource.deregRequestPublic(post_body);
		}
		else if (pathParameters.startsWith("authRequest"))
		{
			json_body = fidoUafResource.getAuthReq();
		}
		else if (pathParameters.startsWith("authResponse"))
		{
			String post_body = event.get("body").toString();
			logger.info("The auth Response is " + post_body);
			String post_body_b64 = Base64.getEncoder().encodeToString(post_body.getBytes());
			logger.info("The B64 encoded auth Response is " + post_body_b64);
			AuthenticatorRecord[] ar_response = fidoUafResource.processAuthResponse(post_body);
			json_body = gson.toJson(ar_response);
			
		}
		else if (pathParameters.startsWith("uaf/facets"))
		{
			json_body = gson.toJson(fidoUafResource.facets());
		}
		/*
		DynamoDB dynamoDB = new DynamoDB(ddb);
		Table userTable = dynamoDB.getTable(UserTableName);
		GetItemSpec spec = new GetItemSpec().withPrimaryKey("sub", user_identifier);
        try {
        	logger.debug("Attempting to read the item...");
            Item outcome = userTable.getItem(spec);
            logger.debug("GetItem succeeded: " + outcome.toJSONPretty());
            testResults.put("DynamoDB", "passed");
        }
        catch (Exception e) {
        	logger.error("Unable to read item: " + user_identifier);
        	logger.error(e.getMessage());
        }
        */
        //responseBody.put("message", user_identifier);

        responseBody.put("testResults", testResults);
        JSONObject headerJson = new JSONObject();
        headerJson.put("x-custom-header", "my custom header value");
        headerJson.put("Access-Control-Allow-Origin", "*");
        headerJson.put("Set-Cookie", "token=; Secure; HttpOnly; Domain=api.mr-b.click");

        responseJson.put("isBase64Encoded", false);
        responseJson.put("statusCode", responseCode);
        responseJson.put("headers", headerJson);
        //responseJson.put("body", responseBody.toString());  
        responseJson.put("body", json_body);

        logger.info(responseJson.toJSONString());
        OutputStreamWriter writer = new OutputStreamWriter(outputStream, "UTF-8");
        writer.write(responseJson.toJSONString());  
        writer.close();
    }

	private String checkCookies(String Cookies){
		//cookies are delimited by "; "
		//cookie values are key=value pairs
		String[] cookies = Cookies.split(";");
		for (int i = 0; i < cookies.length; i++) {
			String cookie = cookies[i].trim();
			//logger.info("cookie number " + i + " is " + cookie);
			String[] key_value = cookie.split("=",2);
			if (key_value[0] == "token")
			{
				return key_value[1];
			}
		}
		return "";
	}


}