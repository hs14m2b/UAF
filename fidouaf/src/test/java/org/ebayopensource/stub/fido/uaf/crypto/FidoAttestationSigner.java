package org.ebayopensource.stub.fido.uaf.crypto;

public interface FidoAttestationSigner {

    public byte[] signWithAttestationCert(byte[] dataForSigning);
}
