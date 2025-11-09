package org.example;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.BDDAssertions.then;
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
                "Test User <test@example.com>", new Date(), new SignWithRsaPrivateKey(rsaPriv),
                rsaPub,
                KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER,
                null,
                0
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

        KeyPair keyPairSign = PGPKeyConversionUtils.pemFileToKeyPair(Files.readString(Path.of("src/test/resources/org/example/bob-private-sign.pem")));
        RSAPublicKey signPublic = (RSAPublicKey) keyPairSign.getPublic();
        PrivateKey signPrivate = keyPairSign.getPrivate();

        KeyPair keyPairEncrypt = PGPKeyConversionUtils.pemFileToKeyPair(Files.readString(Path.of("src/test/resources/org/example/bob-private-encrypt.pem")));
        RSAPublicKey encryptPublic = (RSAPublicKey) keyPairEncrypt.getPublic();

        String userId = "Bob Babbage <bob@openpgp.example>";
        Date creationDate = Date.from(Instant.parse("2019-10-15T10:18:26Z"));

        PGPPublicKeyRing ring = ExternalPGPPublicKeyGenerator.generate(
                userId, creationDate, new SignWithRsaPrivateKey(signPrivate),
                signPublic,
                KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER,
                encryptPublic,
                KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE
        );

        assertNotNull(ring);
        then(ring.size()).isEqualTo(2);
        then(ring.getPublicKey(Hex.decode("D1A66E1A23B182C9980F788CFBFCC82A015E7330"))).isNotNull();
        then(ring.getPublicKey(Hex.decode("1DDCE15F09217CEE2F3B37607C2FAA4DF93C37B2"))).isNotNull();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
        ring.encode(armorOut);
        armorOut.close();

        String armoredKey = out.toString();
        System.out.println("Generated PGP Public Key:\n" + armoredKey);

        assertTrue(armoredKey.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

}
