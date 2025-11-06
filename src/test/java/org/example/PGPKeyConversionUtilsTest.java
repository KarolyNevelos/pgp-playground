package org.example;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;

class PGPKeyConversionUtilsTest {

    @Test
    void privatePgpKeyToPrivatePemKey() throws Exception {
        String pgpPrivateKey = Files.readString(Path.of("src/test/resources/org/example/bob-private.asc"));
        String pemPrivateKey1 = PGPKeyConversionUtils.pgpPrivateToPem(pgpPrivateKey, 0);
        System.out.println(pemPrivateKey1);
        String pemPrivateKey2 = PGPKeyConversionUtils.pgpPrivateToPem(pgpPrivateKey, 1);
        System.out.println(pemPrivateKey2);
    }

    @Test
    void privatePemKeyToPrivatePgpKey() throws Exception {
        String pemPrivateKey = Files.readString(Path.of("src/test/resources/org/example/bob-private-sign.pem"));
        String pgpPrivateKey = PGPKeyConversionUtils.pemPrivateToPgp(pemPrivateKey, Date.from(Instant.parse("2019-10-15T10:18:26Z")), "Bob Babbage <bob@openpgp.example>");

        System.out.println(pgpPrivateKey);
    }

    @Test
    void publicPgpKeyToPublicPemKey() throws Exception {
        String pgpPublicKey = Files.readString(Path.of("src/test/resources/org/example/bob-public.asc"));
        String pemPublicKey1 = PGPKeyConversionUtils.pgpPublicToPem(pgpPublicKey, 0);
        System.out.println(pemPublicKey1);
        String pemPublicKey2 = PGPKeyConversionUtils.pgpPublicToPem(pgpPublicKey, 1);
        System.out.println(pemPublicKey2);
    }

    @Test
    void privatePemKeyToPublicPgpKey() throws Exception {
        String pemPrivateKey = Files.readString(Path.of("src/test/resources/org/example/bob-private-sign.pem"));
        String pgpPublicKey = PGPKeyConversionUtils.pemPublicToPgp(pemPrivateKey, Date.from(Instant.parse("2019-10-15T10:18:26Z")), "Bob Babbage <bob@openpgp.example>");

        System.out.println(pgpPublicKey);
    }
}