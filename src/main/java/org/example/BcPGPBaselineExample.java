package org.example;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.*;

import java.io.*;
import java.security.SecureRandom;
import java.util.Date;

public class BcPGPBaselineExample {

    public static void main(String[] args) throws Exception {
        // Normally you would load real keys from a keyring,
        // but for demonstration we’ll just assume you already have them.
        PGPPublicKey recipientKey = KeyHelper.loadPublicKey("bob-public.asc");
        PGPPrivateKey signingKey = KeyHelper.loadPrivateKey("bob-private.asc");

        // STEP 1️⃣ — Create Bouncy Castle operator implementations
//        PGPContentSignerBuilder signerBuilder =
//                new BcPGPContentSignerBuilder(
//                        PublicKeyAlgorithmTags.RSA_SIGN,
//                        HashAlgorithmTags.SHA256);
        PGPContentSignerBuilder signerBuilder =
                new CustomContentSignerBuilder(
                        PublicKeyAlgorithmTags.RSA_SIGN,
                        HashAlgorithmTags.SHA256,
                        "src\\main\\resources\\org\\example\\bob-private.pem");

        DebuggableDataEncryptorBuilder encryptorBuilder =
                (DebuggableDataEncryptorBuilder) new DebuggableDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom());

        // STEP 2️⃣ — Initialize signature generator
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(signerBuilder);
        sigGen.init(PGPSignature.BINARY_DOCUMENT, signingKey);

        // Add metadata (optional)
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        spGen.addSignerUserID(false, "Bob Babbage <bob@openpgp.example>");
        sigGen.setHashedSubpackets(spGen.generate());

        // STEP 3️⃣ — Sign literal data (no compression)
        ByteArrayOutputStream literalOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();

        String message = "Hello world — signed and encrypted, but not compressed!";
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

        try (ByteArrayInputStream pgpBinary = new ByteArrayInputStream(encryptedOut.toByteArray());
             FileOutputStream fileOut = new FileOutputStream("baseline-message.asc");
             ArmoredOutputStream armorOut = new ArmoredOutputStream(fileOut)) {

            armorOut.setHeader("Comment", "SessionKey (hex): " + sessionKeyHex);

            byte[] buffer = new byte[4096];
            int len;
            while ((len = pgpBinary.read(buffer)) > 0) {
                armorOut.write(buffer, 0, len);
            }

            System.out.println("✅ Baseline OpenPGP (sign+encrypt) complete: baseline-message.asc");
            System.out.println("🔑 Session key: " + sessionKeyHex);
        }
    }



    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
