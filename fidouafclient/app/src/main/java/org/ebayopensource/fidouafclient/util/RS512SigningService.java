package org.ebayopensource.fidouafclient.util;

import static io.jsonwebtoken.SignatureAlgorithm.RS512;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import android.util.Base64;
import java.util.Map;
import android.util.Log;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public final class RS512SigningService{

	private static final SignatureAlgorithm SIGNATURE_ALGORITHM = RS512;
	private static final String RSA_PRIVATE_KEY_NAME = "rsa_private_key";
	private static final String RSA_PEM_PRIVATE_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDvw99j9kTqx8VXAt5ajnMMJhZ6GLGTQwZbqSfa7SFYOjz8y/lT0UYL9X6oPOccQDl26tnblcdXnlYXKN5C2SSFfeLk4H+VJxMWJnRMhTYBXMyIqtfzhCYtNyDaYzIHt5vJTE+3/KAOQ75JR0JDrEC811VTUd8YZYazXL5i8f8gzjOjW167aavCLjT+DAl2G7Fs0RKFyjfjS4YjSv8dFgenMtvwpv9hylgbHCvIGy69GDNBZbFgi+O4wrXhZVx24seMQBF9EpLt50kmrOMRF4y9jsbt73XwG3UeqZF0fcAm+MPzE5iT98PNiXLObDWLraVmqDdzQffqQEh8gwPXRMmxAgMBAAECggEAaAVx2LuSgM21Bx/+eglNTpsDq2slN3+ftYq4+NliWxXBOegAvuWPX0bd8X2iwvX2OGqBpCviNVhDf37ClvwARU4tbyEbGQm/1R9P25b7rDGnpy9/y22s5ncBcN4SaZi2JOpPt8IJasbnOoGI9TU5TPSbVy+w+7Oocg6tpt3Y01Drr+awVTW7jhtdf/nNIIqtFyfGunO7wjdmMqeUAFFW4hbX4Y/Ngjoijf4VU3Prfou7Thgx7I2c5KX1UnQWwjBuUMtSdSxPr0X709HWNxoPvOpMw7aR1nQ4SE+K4r5VTqGWTGtDksToSdyeMR3/D2QCK3IAsGsWffbjKi890fakQQKBgQD/pnu+Yoyk68SY4JgZguflZQI2a/nFZ9tCN/Nl8+KkD7knhiAwOt5n5CZgg8zINKhC/rDUiSu7K5t3TlTlTk7SpOPPDcZ6K1xorrdmGc0q3+GFVZiriGqBbmPvwvHZBvMYlbMP86eGcZsvNnmGvdvqDvb8OnlrMkY2esx9ejRgGQKBgQDwF9O2Y48hJce6bVt5OaOyhAg/+djkBLA23RLOAQ882GKOhCdcdGIMwUk6S29WFELwk8eUvhj9YGy1KFBMmtmofOw+QKtpDImIzVWVYBcZXnSLmIHQYhvDpkL0rWchr1oNTlzsXjj2/SaCWeb+mX+kBzB6c1FlhDPdCajW3PKJWQKBgQDgJaM3gQaZjxI3jCwvqgQSsCZpevBq8a1feNkSmewsNpD7o3DTeLoJ0xMG6miBXRHuc4qtPnu2RvyvdWGgD7GypNoMb6KG+T+zlQS+I38syVDda/hI5XmkdBpxXLZZt+sqsg5mvRY0HaWXlqakyhBoPqi067wLje/b0n06wwvq+QKBgGmU0NFgLs0Q5Cgjdxp0MnyKe2ZG5Q5A0Y0O4voclSrYrV6m1vhdZdDeHum3ypo8BsPs+NN8VVj3UlbIB6foYNcrOGiX38kubjzurzglLYNGelH5Gv0cZ8E+GCupJbU2e49mao63UK2s3YZtKpvDvNHRJ4xxsdXGsVf+q3TxbObhAoGBAPPvzxA/a+1qk0rTVp2/SmXUWLLfBmsLveIYdfYfiMZ0Unz1FetZkoIQiDPc5faKJt7A666jq/l64uSqG3JE6RYz/ovckcAGS6j1tt77s1XuFa3JIT9ytGWJkviqtOwVZqv32EW55rC/9WGz5T+B40oGLuWNcopp6JWGCY+LgsGa";


	private RSAPrivateKey privateKey;

	public String signToken(final Claims claims, final Map<String, Object> header) {
		Log.i("signToken","Signing token");
		if(claims == null) {
			return null;
		}

		if(privateKey == null) {
			try {
				setRSAPrivateKey();
			} catch(Exception e) {
				Log.e("signToken","Unable to set private key " + e.getMessage());
				throw e;
			}
		}
		return Jwts.builder().setHeader(header).setClaims(claims).signWith(SIGNATURE_ALGORITHM, privateKey).compact();
	}

	private synchronized void setRSAPrivateKey() {
		if(privateKey != null) {
			Log.i("setRSAPrivateKey","Private key already set.");
			return;
		}

		KeyFactory keyFactory = null;

		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch(NoSuchAlgorithmException e) {
			Log.e("setRSAPrivateKey",e.getMessage());
		}

		String privateKeyString = RSA_PEM_PRIVATE_KEY.replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
												.replaceAll("-----END RSA PRIVATE KEY-----", "")
												.replaceAll(" ", "")
												.replaceAll("[\n\r]", "")
												.trim();

		byte[] privateKeyEncoded = Base64.decode(privateKeyString, 3);

		// decode private key
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
		try {
			privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		} catch(InvalidKeySpecException e) {
			Log.e("setRSAPrivateKey",e.getMessage());
		}
	}

}