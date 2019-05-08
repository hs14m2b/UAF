package org.ebayopensource.stub.fido.uaf.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FidoSignerBC implements FidoSigner {
    private static final Logger logger = LogManager.getLogger(FidoSignerBC.class);

    public byte[] sign(byte[] dataToSign, KeyPair keyPair) {
        try {
            BigInteger[] signatureGen = NamedCurve.signAndFromatToRS(keyPair.getPrivate(),
                    SHA.sha(dataToSign, "SHA-256"));

    		logger.info(" : pub 		   : " + Base64.encodeBase64URLSafeString(KeyCodec.getPubKeyAsRawBytes(keyPair.getPublic())));
    		logger.info(" : dataForSigning : "
    				+ Base64.encodeBase64URLSafeString(SHA.sha(dataToSign, "SHA-256")));
    		logger.info(" : signature 	   : "
    				+ Base64.encodeBase64URLSafeString(Asn1.getEncoded(signatureGen)));

            boolean verify = NamedCurve.verify(
                    KeyCodec.getPubKeyAsRawBytes(keyPair.getPublic()),
                    SHA.sha(dataToSign, "SHA-256"),
                    Asn1.decodeToBigIntegerArray(Asn1.getEncoded(signatureGen)));
            if (!verify) {
                throw new RuntimeException("Signatire match fail");
            }
            byte[] ret = Asn1.toRawSignatureBytes(signatureGen);

            return ret;
        } catch (NoSuchAlgorithmException ex) {
        	throw new RuntimeException(ex);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }


    }
}