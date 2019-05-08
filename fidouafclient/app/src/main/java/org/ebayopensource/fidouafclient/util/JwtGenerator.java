package org.ebayopensource.fidouafclient.util;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import android.util.Log;

public class JwtGenerator {

    private static final String TOKEN_TYPE = "JWT";
    private static final String HEADER_JTI = "jti";
    private static final String HEADER_NONCE = "nonce";
    private static final String HEADER_TYP = "typ";
    RS512SigningService signingService = new RS512SigningService();

    public String generateJwt(String clientId, String audience){
        Log.i("generateJwt","Calculating issue date time.");
        final long issueTime = System.currentTimeMillis();
        final Date issuedAt = new Date(issueTime);

        Log.i("generateJwt","Calculating expiry date time.");
        final long expiryTime = issueTime + TimeUnit.SECONDS.toMillis(600);
        final Date expiresAt = new Date(expiryTime);
        Claims tokenClaims = Jwts.claims()	.setIssuer(clientId)
                .setSubject(clientId)
                .setAudience(audience)
                .setExpiration(expiresAt)
                .setIssuedAt(issuedAt);
        Header header = getHeader(tokenClaims);
        return signingService.signToken(tokenClaims, header);
    }
    private Header getHeader(Claims defaultClaims) {
        Header headers = Jwts.header();
        for(Map.Entry<String, Object> entry : defaultClaims.entrySet()) {
            headers.put(entry.getKey(), entry.getValue());
        }

        headers.put(HEADER_JTI, UUID.randomUUID().toString());
        headers.put(HEADER_NONCE, UUID.randomUUID().toString());
        headers.put(HEADER_TYP, TOKEN_TYPE);
        return headers;
    }
}
