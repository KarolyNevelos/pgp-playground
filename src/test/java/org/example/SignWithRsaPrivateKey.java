package org.example;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.function.Function;

class SignWithRsaPrivateKey implements Function<byte[], byte[]> {
    private final PrivateKey rsaPriv;

    public SignWithRsaPrivateKey(PrivateKey rsaPriv) {
        this.rsaPriv = rsaPriv;
    }

    @Override
    public byte[] apply(byte[] digest) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(rsaPriv);
            sig.update(digest);
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
