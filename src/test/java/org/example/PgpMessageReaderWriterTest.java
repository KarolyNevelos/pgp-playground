package org.example;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;

import static org.assertj.core.api.Assertions.from;
import static org.assertj.core.api.BDDAssertions.then;

public class PgpMessageReaderWriterTest {

    private final PGPPublicKey bobPublicKey = KeyHelper.loadPublicKey("bob-public.asc");
    private final PGPPrivateKey bobPrivateKey = KeyHelper.loadPrivateKey("bob-private.asc");
    private final PGPPublicKey cooperPublicKey = KeyHelper.loadPublicKey("cooper-public.asc");
    private final PGPPrivateKey cooperPrivateKey = KeyHelper.loadPrivateKey("cooper-private.asc");

    public static final String MESSAGE_TEXT = "Hello world — signed and encrypted, but not compressed!";

    public PgpMessageReaderWriterTest() throws Exception {
    }

    @Test
    void standardWriteBobStandardReadBob() throws Exception {
        // Given
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createStandard(bobPrivateKey, bobPublicKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createStandard(bobPrivateKey, bobPublicKey);
        String encrypted = pgpMessageWriter.encryptAndSignMessage(MESSAGE_TEXT);
        System.out.println(encrypted);

        // When
        PgpMessageReader.MessageResult messageResult = pgpMessageReader.decryptAndVerify(new ByteArrayInputStream(encrypted.getBytes()));

        // Then
        then(messageResult)
                .returns(MESSAGE_TEXT, from(PgpMessageReader.MessageResult::getMessage))
                .returns(true, from(PgpMessageReader.MessageResult::isVerified))
                .returns(true, from(PgpMessageReader.MessageResult::isIntegrityChecked));
    }

    @Test
    void standardWriteBobStandardReadCooper() throws Exception {
        // Given
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createStandard(bobPrivateKey, cooperPublicKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createStandard(cooperPrivateKey, bobPublicKey);
        String encrypted = pgpMessageWriter.encryptAndSignMessage(MESSAGE_TEXT);
        System.out.println(encrypted);

        // When
        PgpMessageReader.MessageResult messageResult = pgpMessageReader.decryptAndVerify(new ByteArrayInputStream(encrypted.getBytes()));

        // Then
        then(messageResult)
                .returns(MESSAGE_TEXT, from(PgpMessageReader.MessageResult::getMessage))
                .returns(true, from(PgpMessageReader.MessageResult::isVerified))
                .returns(true, from(PgpMessageReader.MessageResult::isIntegrityChecked));
    }

    @Test
    void customWriteBobStandardReadCooper() throws Exception {
        // Given
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createCustom("src\\test\\resources\\org\\example\\bob-private.pem", cooperPublicKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createStandard(cooperPrivateKey, bobPublicKey);
        String encrypted = pgpMessageWriter.encryptAndSignMessage(MESSAGE_TEXT);
        System.out.println(encrypted);

        // When
        PgpMessageReader.MessageResult messageResult = pgpMessageReader.decryptAndVerify(new ByteArrayInputStream(encrypted.getBytes()));

        // Then
        then(messageResult)
                .returns(MESSAGE_TEXT, from(PgpMessageReader.MessageResult::getMessage))
                .returns(true, from(PgpMessageReader.MessageResult::isVerified))
                .returns(true, from(PgpMessageReader.MessageResult::isIntegrityChecked));
    }

    @Test
    void standardWriteCooperCustomerReadBob() throws Exception {
        // Given
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createStandard(cooperPrivateKey, bobPublicKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createCustom("src\\test\\resources\\org\\example\\bob-private.pem", cooperPublicKey);
        String encrypted = pgpMessageWriter.encryptAndSignMessage(MESSAGE_TEXT);
        System.out.println(encrypted);

        // When
        PgpMessageReader.MessageResult messageResult = pgpMessageReader.decryptAndVerify(new ByteArrayInputStream(encrypted.getBytes()));

        // Then
        then(messageResult)
                .returns(MESSAGE_TEXT, from(PgpMessageReader.MessageResult::getMessage))
                .returns(true, from(PgpMessageReader.MessageResult::isVerified))
                .returns(true, from(PgpMessageReader.MessageResult::isIntegrityChecked));
    }

    @Test
    void customWriteBobCustomReadBob() throws Exception {
        // Given
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createCustom("src\\test\\resources\\org\\example\\bob-private.pem", bobPublicKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createCustom("src\\test\\resources\\org\\example\\bob-private.pem", bobPublicKey);
        String encrypted = pgpMessageWriter.encryptAndSignMessage(MESSAGE_TEXT);
        System.out.println(encrypted);

        // When
        PgpMessageReader.MessageResult messageResult = pgpMessageReader.decryptAndVerify(new ByteArrayInputStream(encrypted.getBytes()));

        // Then
        then(messageResult)
                .returns(MESSAGE_TEXT, from(PgpMessageReader.MessageResult::getMessage))
                .returns(true, from(PgpMessageReader.MessageResult::isVerified))
                .returns(true, from(PgpMessageReader.MessageResult::isIntegrityChecked));
    }
}
