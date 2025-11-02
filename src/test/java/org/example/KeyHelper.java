package org.example;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;

class KeyHelper {

    private KeyHelper(){}

    static PGPPrivateKey loadPrivateKey(String filePath) throws Exception {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream("src\\test\\resources\\org\\example\\" + filePath))) {
            PGPSecretKeyRingCollection keyRings =
                    new PGPSecretKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn),
                            new BcKeyFingerprintCalculator());

            for (PGPSecretKeyRing ring : keyRings) {
                for (PGPSecretKey key : ring) {
                    if (key.isSigningKey()) {
                        return key.extractPrivateKey(
                                new BcPBESecretKeyDecryptorBuilder(
                                        new BcPGPDigestCalculatorProvider()).build("".toCharArray()));
                    }
                }
            }
        }
        throw new IllegalArgumentException("No signing key found in " + filePath);
    }

    static PGPPublicKey loadPublicKey(String filePath) throws Exception {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream("src\\test\\resources\\org\\example\\" + filePath))) {
            PGPPublicKeyRingCollection keyRings =
                    new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn),
                            new BcKeyFingerprintCalculator());

            for (PGPPublicKeyRing ring : keyRings) {
                for (PGPPublicKey key : ring) {
                    if (key.isEncryptionKey()) {
                        return key;
                    }
                }
            }
        }
        throw new IllegalArgumentException("No encryption key found in " + filePath);
    }
}