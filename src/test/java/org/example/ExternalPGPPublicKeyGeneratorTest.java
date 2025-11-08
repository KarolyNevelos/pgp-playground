package org.example;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ExternalPGPPublicKeyGeneratorTest {

    @Test
    void testGeneratePGPPublicKeyWithExternalSigner() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        RSAPublicKey rsaPub = (RSAPublicKey) kp.getPublic();
        PrivateKey rsaPriv = kp.getPrivate();

        PGPPublicKeyRing ring = ExternalPGPPublicKeyGenerator.generate(
                rsaPub,
                "Test User <test@example.com>",
                new Date(),
                new SignerImpl(rsaPriv)
        );

        assertNotNull(ring);
        assertTrue(ring.getPublicKeys().hasNext());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
        ring.encode(armorOut);
        armorOut.close();

        String armoredKey = out.toString();
        System.out.println("Generated PGP Public Key:\n" + armoredKey);

        assertTrue(armoredKey.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    @Test
    void testGenerateBobsPublicKey() throws Exception {

        KeyPair kp = PGPKeyConversionUtils.pemFileToKeyPair(Files.readString(Path.of("src/test/resources/org/example/bob-private-sign.pem")));
        RSAPublicKey rsaPub = (RSAPublicKey) kp.getPublic();
        PrivateKey rsaPriv = kp.getPrivate();

        String userId = "Bob Babbage <bob@openpgp.example>";
        Date creationDate = Date.from(Instant.parse("2019-10-15T10:18:26Z"));

        PGPPublicKeyRing ring = ExternalPGPPublicKeyGenerator.generate(
                rsaPub,
                userId,
                creationDate,
                new SignerImpl(rsaPriv)
        );

        assertNotNull(ring);
        assertTrue(ring.getPublicKeys().hasNext());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
        ring.encode(armorOut);
        armorOut.close();

        String armoredKey = out.toString();
        System.out.println("Generated PGP Public Key:\n" + armoredKey);

        assertTrue(armoredKey.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    private static class SignerImpl implements Function<byte[], byte[]> {
        private final PrivateKey rsaPriv;

        public SignerImpl(PrivateKey rsaPriv) {
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
}
