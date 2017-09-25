package org.ebayopensource.fido.uaf.crypto;

import android.content.Context;
import android.os.Build;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Created by JP20818 on 2017/09/25.
 */

public abstract class FidoKeystore {

    public static FidoKeystore createKeyStore(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return new FidoKeystoreAndroidM();
        }

        return new FidoKeyStoreBC();
    }

    public abstract KeyPair generateKeyPair(String username);

    public abstract KeyPair getKeyPair(String username);

    public abstract PublicKey getPublicKey(String username);

    public abstract X509Certificate getCertificate(String username);

    public abstract FidoSigner getSigner(String username);
}
