package org.ebayopensource.stub.fido.uaf.crypto;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;

public class FixedCertFidoAttestationSigner implements FidoAttestationSigner {

    private static final String TAG = FixedCertFidoAttestationSigner.class.getSimpleName();
	private Logger logger = LogManager.getLogger(this.getClass().getName());
	KeyPair kp = null;
	
	public FixedCertFidoAttestationSigner(KeyPair keyPair)
	{
		kp = keyPair;
	}
	
    public byte[] signWithAttestationCert(byte[] dataForSigning) {
        try {
            PrivateKey priv = kp.getPrivate();
                    //KeyCodec.getPrivKey(Base64url.decode(AttestCert.priv));

            //Log.i(TAG, " : dataForSigning : "
            //        + Base64url.encodeToString(dataForSigning));
            logger.info(TAG +" : dataForSigning : " + Base64url.encodeToString(dataForSigning));
            BigInteger[] signatureGen = NamedCurve.signAndFromatToRS(priv,
                    SHA.sha(dataForSigning, "SHA-256"));
	          //byte[] signatureGen = NamedCurve.sign(SHA.sha(dataForSigning, "SHA-256"),priv);

            boolean verify = NamedCurve.verify(
                    KeyCodec.getPubKeyAsRawBytes(kp.getPublic()),
                    SHA.sha(dataForSigning, "SHA-256"),
                    Asn1.decodeToBigIntegerArray(Asn1.getEncoded(signatureGen)));
	          //boolean verify = NamedCurve.verify(kp.getPublic(),  SHA.sha(dataForSigning, "SHA-256"),  signatureGen);
            if (!verify) {
                throw new RuntimeException("Signature match fail");
            }
            byte[] ret = Asn1.toRawSignatureBytes(signatureGen);
            //Log.i(TAG, " : signature : " + Base64url.encodeToString(ret));

            return ret;
        } catch(Exception e) {
            throw new RuntimeException(e);
        }
    }
}
