package org.example;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;

class PGPKeyConversionUtilsTest {

    @Test
    void privatePgpKeyToPrivatePemKey() throws Exception {
        String pgpPrivateKey = Files.readString(Path.of("src/main/resources/org/example/bob-private.asc"));
        String pemPrivateKey = PGPKeyConversionUtils.pgpPrivateToPem(pgpPrivateKey);

        System.out.println(pemPrivateKey);
    }

    @Test
    void privatePemKeyToPrivatePgpKey() throws Exception {
        String pemPrivateKey = Files.readString(Path.of("src/main/resources/org/example/bob-private.pem"));
        String pgpPrivateKey = PGPKeyConversionUtils.pemPrivateToPgp(pemPrivateKey, Date.from(Instant.parse("2019-10-15T10:18:26Z")), "Bob Babbage <bob@openpgp.example>");

        System.out.println(pgpPrivateKey);
    }

    @Test
    void publicPgpKeyToPublicPemKey() throws Exception {
        String pgpPublicKey = Files.readString(Path.of("src/main/resources/org/example/bob-public.asc"));
        String pemPublicKey = PGPKeyConversionUtils.pgpPublicToPem(pgpPublicKey);

        System.out.println(pemPublicKey);
    }

    @Test
    void privatePemKeyToPublicPgpKey() throws Exception {
        String pemPrivateKey = Files.readString(Path.of("src/main/resources/org/example/bob-private.pem"));
        String pgpPublicKey = PGPKeyConversionUtils.pemPublicToPgp(pemPrivateKey, Date.from(Instant.parse("2019-10-15T10:18:26Z")), "Bob Babbage <bob@openpgp.example>");

        System.out.println(pgpPublicKey);
    }
}