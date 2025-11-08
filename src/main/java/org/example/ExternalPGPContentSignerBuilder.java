package org.example;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;

import java.util.function.Function;

public class ExternalPGPContentSignerBuilder implements PGPContentSignerBuilder {
    private final int keyAlgorithm;
    private final int hashAlgorithm;
    private final Function<byte[], byte[]> externalSigner;
    private final long keyid;

    public ExternalPGPContentSignerBuilder(
            int keyAlgorithm,
            int hashAlgorithm,
            Function<byte[], byte[]> externalSigner, long keyid
    ) {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.externalSigner = externalSigner;
        this.keyid = keyid;
    }

    @Override
    public PGPContentSigner build(int signatureType, PGPPrivateKey privateKey) {
        return new ExternalPGPContentSigner(keyAlgorithm, hashAlgorithm, signatureType, keyid, externalSigner);
    }

}
