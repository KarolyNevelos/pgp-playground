package org.example;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;

import java.util.function.Function;

public class ExternalPGPContentSignerBuilder implements PGPContentSignerBuilder {
    private final int keyAlgorithm;
    private final int hashAlgorithm;
    private final Function<byte[], byte[]> externalSigner;
    private final long keyId;

    public ExternalPGPContentSignerBuilder(
            int keyAlgorithm,
            int hashAlgorithm,
            long keyId,
            Function<byte[], byte[]> externalSigner
    ) {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.externalSigner = externalSigner;
        this.keyId = keyId;
    }

    @Override
    public PGPContentSigner build(int signatureType, PGPPrivateKey privateKey) {
        return new ExternalPGPContentSigner(keyAlgorithm, hashAlgorithm, signatureType, keyId, externalSigner);
    }

}
