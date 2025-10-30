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
        PGPPublicKey recipientKey = loadPublicKey("bob-public.asc");
        PGPPrivateKey signingKey = loadPrivateKey("bob-private.asc", "".toCharArray());

        // STEP 1️⃣ — Create Bouncy Castle operator implementations
        PGPContentSignerBuilder signerBuilder =
                new BcPGPContentSignerBuilder(
                        PublicKeyAlgorithmTags.RSA_SIGN,
                        HashAlgorithmTags.SHA256);

        DebuggableDataEncryptorBuilder encryptorBuilder =
                (DebuggableDataEncryptorBuilder) new DebuggableDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom());

        // STEP 2️⃣ — Initialize signature generator
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(signerBuilder);
        sigGen.init(PGPSignature.BINARY_DOCUMENT, signingKey);

        // Add metadata (optional)
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        spGen.setSignerUserID(false, "signer@example.com");
        sigGen.setHashedSubpackets(spGen.generate());

        // STEP 3️⃣ — Sign literal data (no compression)
        ByteArrayOutputStream literalOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();

        OutputStream litOut = literalGen.open(
                literalOut,
                PGPLiteralData.BINARY,
                "message.txt",
                new Date(),
                new byte[4096]
        );

        String message = "Hello world — signed and encrypted, but not compressed!";
        byte[] messageBytes = message.getBytes();
        litOut.write(messageBytes);
        litOut.close();
        literalGen.close();

        byte[] literalData = literalOut.toByteArray();

        // STEP 4️⃣ — Compute signature packet
        sigGen.update(messageBytes); // Feed data into signature
        PGPSignature signature = sigGen.generate();

        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        sigGen.generateOnePassVersion(false).encode(signedOut);
        signedOut.write(literalData);
        signature.encode(signedOut);

        byte[] signedData = signedOut.toByteArray();

        // STEP 5️⃣ — Encrypt
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptorBuilder);
        encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(recipientKey));

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (OutputStream encryptedStream = encGen.open(encryptedOut, signedData.length)) {
            encryptedStream.write(signedData);
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

    // ----------------------------------------------------
    // Helper: Load PGP keys from ASCII-armored files
    // ----------------------------------------------------
    private static PGPPublicKey loadPublicKey(String filePath) throws Exception {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream("src\\main\\resources\\org\\example\\" + filePath))) {
            PGPPublicKeyRingCollection keyRings =
                    new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn),
                            new BcKeyFingerprintCalculator());

            for (PGPPublicKeyRing ring : keyRings) {
                for (PGPPublicKey key : ring) {
                    if (key.isEncryptionKey()) {
                        return key;
                    }
                }
            }
        }
        throw new IllegalArgumentException("No encryption key found in " + filePath);
    }

    private static PGPPrivateKey loadPrivateKey(String filePath, char[] password) throws Exception {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream("src\\main\\resources\\org\\example\\" + filePath))) {
            PGPSecretKeyRingCollection keyRings =
                    new PGPSecretKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn),
                            new BcKeyFingerprintCalculator());

            for (PGPSecretKeyRing ring : keyRings) {
                for (PGPSecretKey key : ring) {
                    if (key.isSigningKey()) {
                        return key.extractPrivateKey(
                                new BcPBESecretKeyDecryptorBuilder(
                                        new BcPGPDigestCalculatorProvider()).build(password));
                    }
                }
            }
        }
        throw new IllegalArgumentException("No signing key found in " + filePath);
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
