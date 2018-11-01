package org.ebayopensource.stub.fido.uaf.crypto;

import java.security.KeyPair;

public interface FidoSigner {

    public abstract byte[] sign(byte[] dataToSign, KeyPair keyPair);

}
