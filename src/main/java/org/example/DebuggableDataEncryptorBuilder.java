package org.example;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;

public class DebuggableDataEncryptorBuilder extends BcPGPDataEncryptorBuilder {

    private byte[] lastSessionKey;

    public DebuggableDataEncryptorBuilder(int encAlgorithm) {
        super(encAlgorithm);
    }

    @Override
    public PGPDataEncryptor build(byte[] key) throws PGPException {
        // Intercept the key that BC passes in (the session key)
        this.lastSessionKey = key.clone();
        return super.build(key);
    }

    public byte[] getLastSessionKey() {
        return lastSessionKey;
    }
}