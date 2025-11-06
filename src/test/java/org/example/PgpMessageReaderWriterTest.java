package org.example;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;

import static org.assertj.core.api.Assertions.from;
import static org.assertj.core.api.BDDAssertions.then;

public class PgpMessageReaderWriterTest {

    private final PGPPublicKey bobPublicSignKey = KeyHelper.loadPublicKey("bob-public.asc", KeyFlags.SIGN_DATA);
    private final PGPPublicKey bobPublicEncryptKey = KeyHelper.loadPublicKey("bob-public.asc", KeyFlags.ENCRYPT_COMMS);
    private final PGPPrivateKey bobPrivateSignKey = KeyHelper.loadPrivateKey("bob-private.asc", KeyFlags.SIGN_DATA);
    private final PGPPrivateKey bobPrivateEncryptKey = KeyHelper.loadPrivateKey("bob-private.asc", KeyFlags.ENCRYPT_COMMS);
    private final PGPPublicKey cooperPublicSignKey = KeyHelper.loadPublicKey("cooper-public.asc", KeyFlags.SIGN_DATA);
    private final PGPPublicKey cooperPublicEncryptKey = KeyHelper.loadPublicKey("cooper-public.asc", KeyFlags.ENCRYPT_COMMS);
    private final PGPPrivateKey cooperPrivateSignKey = KeyHelper.loadPrivateKey("cooper-private.asc", KeyFlags.SIGN_DATA);
    private final PGPPrivateKey cooperPrivateEncryptKey = KeyHelper.loadPrivateKey("cooper-private.asc", KeyFlags.ENCRYPT_COMMS);

    public static final String MESSAGE_TEXT = "Hello world — signed and encrypted, but not compressed!";

    public PgpMessageReaderWriterTest() throws Exception {
    }

    @Test
    void standardWriteBobStandardReadBob() throws Exception {
        // Given
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createStandard(bobPrivateSignKey, bobPublicEncryptKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createStandard(bobPublicSignKey, bobPrivateEncryptKey);
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
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createStandard(bobPrivateSignKey, cooperPublicEncryptKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createStandard(bobPublicSignKey, cooperPrivateEncryptKey);
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
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createCustom("src\\test\\resources\\org\\example\\bob-private-sign.pem", cooperPublicEncryptKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createStandard(bobPublicSignKey, cooperPrivateEncryptKey);
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
    void standardWriteCooperCustomReadBob() throws Exception {
        // Given
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createStandard(cooperPrivateEncryptKey, bobPublicSignKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createCustom(cooperPublicEncryptKey, "src\\test\\resources\\org\\example\\bob-private-sign.pem");
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
        PgpMessageWriter pgpMessageWriter = PgpMessageWriter.createCustom("src\\test\\resources\\org\\example\\bob-private-encrypt.pem", bobPublicSignKey);
        PgpMessageReader pgpMessageReader = PgpMessageReader.createCustom(bobPublicEncryptKey, "src\\test\\resources\\org\\example\\bob-private-sign.pem");
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
