package org.example;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

public class KeyIdCalculator {
    private KeyIdCalculator(){}

    static long getKeyId(PrivateKey privateKey, Date creationDate) throws IOException, PGPException {
        BigInteger n = ((RSAPrivateKey)privateKey).getModulus(); // modulus
        BigInteger e = ((RSAPrivateCrtKey) privateKey).getPublicExponent();

        // Create RSA public key structure
        RSAPublicBCPGKey rsaKey = new RSAPublicBCPGKey(n, e);

        // Create a V4 PublicKeyPacket
        PublicKeyPacket pubKeyPacket = new PublicKeyPacket(
                4,                             // Version 4
                PublicKeyAlgorithmTags.RSA_GENERAL,
                creationDate,                    // Creation time
                rsaKey
        );

        PGPPublicKey pgpPub = new PGPPublicKey(pubKeyPacket, new JcaKeyFingerprintCalculator());
        return pgpPub.getKeyID();
    }
}
