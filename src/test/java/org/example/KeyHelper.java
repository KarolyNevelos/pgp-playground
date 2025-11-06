package org.example;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;

class KeyHelper {

    private KeyHelper(){}

    static PGPPrivateKey loadPrivateKey(String filePath, int keyFlag) throws Exception {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream("src\\test\\resources\\org\\example\\" + filePath))) {
            PGPSecretKeyRingCollection keyRings =
                    new PGPSecretKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn),
                            new BcKeyFingerprintCalculator());

            for (PGPSecretKeyRing ring : keyRings) {
                for (PGPSecretKey key : ring) {
                    if ((key.getPublicKey().getSignatures().next().getHashedSubPackets().getKeyFlags() & keyFlag) != 0) {
                        System.out.println("Key with fingerprint: " + Hex.toHexString(key.getPublicKey().getFingerprint()) + " features: " + Integer.toHexString(key.getPublicKey().getSignatures().next().getHashedSubPackets().getKeyFlags()));
                        return key.extractPrivateKey(null);
                    }
                }
            }
        }
        throw new IllegalArgumentException("No key found in " + filePath);
    }

    static PGPPublicKey loadPublicKey(String filePath, int keyFlag) throws Exception {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream("src\\test\\resources\\org\\example\\" + filePath))) {
            PGPPublicKeyRingCollection keyRings =
                    new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn),
                            new BcKeyFingerprintCalculator());

            for (PGPPublicKeyRing ring : keyRings) {
                for (PGPPublicKey key : ring) {
                    if ((key.getSignatures().next().getHashedSubPackets().getKeyFlags() & keyFlag) != 0) {
                        System.out.println("Key with fingerprint: " + Hex.toHexString(key.getFingerprint()) + " features: " + Integer.toHexString(key.getSignatures().next().getHashedSubPackets().getKeyFlags()));
                        return key;
                    }
                }
            }
        }
        throw new IllegalArgumentException("No key found in " + filePath);
    }
}