package org.example;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;

public class PgpMessageWriter {

    private final PGPSignatureGenerator sigGen;
    private final PGPPublicKey recipientKey;

    public static PgpMessageWriter createStandard(PGPPrivateKey signingKey, PGPPublicKey encryptionKey) throws PGPException {
        PGPContentSignerBuilder signerBuilder =
                new BcPGPContentSignerBuilder(
                        PublicKeyAlgorithmTags.RSA_SIGN,
                        HashAlgorithmTags.SHA256);

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(signerBuilder);
        sigGen.init(PGPSignature.BINARY_DOCUMENT, signingKey);
        return new PgpMessageWriter(sigGen, encryptionKey);
    }

    public static PgpMessageWriter createCustom(String signersPrivatePemFilePath, PGPPublicKey encryptionKey) throws Exception {
        PGPContentSignerBuilder signerBuilder =
                new CustomContentSignerBuilder(
                        PublicKeyAlgorithmTags.RSA_SIGN,
                        HashAlgorithmTags.SHA256,
                        signersPrivatePemFilePath);

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(signerBuilder);
        sigGen.init(PGPSignature.BINARY_DOCUMENT, null);

        return new PgpMessageWriter(sigGen, encryptionKey);
    }

    public PgpMessageWriter(PGPSignatureGenerator sigGen, PGPPublicKey recipientKey){
        this.sigGen = sigGen;
        this.recipientKey = recipientKey;
    }

    public String encryptAndSignMessage(String message) throws Exception {
        // STEP 1️⃣ — Create Bouncy Castle operator implementations
        DebuggableDataEncryptorBuilder encryptorBuilder =
                (DebuggableDataEncryptorBuilder) new DebuggableDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom());

        // STEP 2️⃣ — Initialize signature generator

        // Add metadata (optional)
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        //spGen.addSignerUserID(false, "Bob Babbage <bob@openpgp.example>");
        sigGen.setHashedSubpackets(spGen.generate());

        // STEP 3️⃣ — Sign literal data (no compression)
        ByteArrayOutputStream literalOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();

        byte[] messageBytes = message.getBytes();

        OutputStream litOut = literalGen.open(
                literalOut,
                PGPLiteralData.BINARY,
                "message.txt",
                new Date(),
                new byte[4096]
        );

        litOut.write(messageBytes);
        litOut.close();
        literalGen.close();

        byte[] literalData = literalOut.toByteArray();

        // STEP 5️⃣ — Encrypt
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptorBuilder);
        encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(recipientKey));

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();


        try (OutputStream encryptedStream = encGen.open(encryptedOut, new byte[4096])) {

            // --- 1️⃣ Write One-Pass Signature Packet ---
            sigGen.generateOnePassVersion(false).encode(encryptedStream);

            encryptedStream.write(literalData);
            sigGen.update(messageBytes);

            PGPSignature signature = sigGen.generate();
            signature.encode(encryptedStream);
        }

        // STEP 5️⃣ — Save final encrypted file in ASCII-armored format
        byte[] sessionKey = encryptorBuilder.getLastSessionKey();
        String sessionKeyHex = toHex(sessionKey);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ByteArrayInputStream pgpBinary = new ByteArrayInputStream(encryptedOut.toByteArray());
             ArmoredOutputStream armorOut = new ArmoredOutputStream(out)) {

            armorOut.setHeader("Comment", "SessionKey (hex): " + sessionKeyHex);

            byte[] buffer = new byte[4096];
            int len;
            while ((len = pgpBinary.read(buffer)) > 0) {
                armorOut.write(buffer, 0, len);
            }

        }
        //System.out.println("🔑 Session key: " + sessionKeyHex);
        return out.toString(StandardCharsets.UTF_8);

    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
