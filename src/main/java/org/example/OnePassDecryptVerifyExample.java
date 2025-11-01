package org.example;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.Security;
import java.util.Iterator;

public class OnePassDecryptVerifyExample {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // --- Load recipient secret key (for decryption) ---
        PGPPrivateKey privateKey = KeyHelper.loadPrivateKey("bob-private.asc");

        // --- Load signer public key (for verification) ---
        PGPPublicKey signingKey = KeyHelper.loadPublicKey("bob-public.asc");

        // --- Input file (the one generated earlier) ---
        try (InputStream in = new BufferedInputStream(new FileInputStream("baseline-message.asc"))) {
            decryptAndVerify(in, privateKey, signingKey);
        }
    }

    private static void decryptAndVerify(InputStream in, PGPPrivateKey recipientKey, PGPPublicKey signingKey)
            throws Exception {

        // Decode ASCII armor
        InputStream decoderStream = PGPUtil.getDecoderStream(in);

        // Parse encrypted data
        PGPObjectFactory pgpFact = new PGPObjectFactory(decoderStream, new BcKeyFingerprintCalculator());
        Object firstObj = pgpFact.nextObject();

        if (!(firstObj instanceof PGPEncryptedDataList)) {
            firstObj = pgpFact.nextObject(); // sometimes first is a marker
        }
        PGPEncryptedDataList encList = (PGPEncryptedDataList) firstObj;

        // Find encrypted session for our key
        PGPPublicKeyEncryptedData encData = null;
        for (Iterator<?> it = encList.getEncryptedDataObjects(); it.hasNext(); ) {
            Object o = it.next();
            if (o instanceof PGPPublicKeyEncryptedData pked) {
                encData = pked;
                break;
            }
        }
        if (encData == null) throw new IllegalStateException("No encrypted data found.");

        // Decrypt data stream
        InputStream clear = encData.getDataStream(
                new BcPublicKeyDataDecryptorFactory(recipientKey)
                //new CustomPrivateKeyDecryptor("src\\main\\resources\\org\\example\\bob-private.pem").buildDecryptorFactory()
        );

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

        // Expect One-Pass Signature + Literal data
        PGPOnePassSignatureList onePassList = null;
        PGPLiteralData literalData = null;
        PGPSignatureList signatureList = null;

        Object obj;
        while ((obj = plainFact.nextObject()) != null) {
            if (obj instanceof PGPOnePassSignatureList list) {
                onePassList = list;
            } else if (obj instanceof PGPLiteralData lit) {
                literalData = lit;
            } else if (obj instanceof PGPSignatureList list) {
                signatureList = list;
            }
        }

        if (onePassList == null || literalData == null || signatureList == null) {
            throw new IllegalStateException("Missing expected PGP packets");
        }

        // Prepare for verification
        PGPOnePassSignature onePass = onePassList.get(0);
        onePass.init(new BcPGPContentVerifierBuilderProvider(), signingKey);

        // Read message and update signature
        try (InputStream litIn = literalData.getInputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            byte[] buf = new byte[4096];
            int len;
            while ((len = litIn.read(buf)) > 0) {
                onePass.update(buf, 0, len);
                out.write(buf, 0, len);
            }

            String plaintext = out.toString("UTF-8");
            System.out.println("📩 Decrypted message:\n" + plaintext);

            // Verify trailing signature
            PGPSignature signature = signatureList.get(0);
            boolean verified = onePass.verify(signature);

            System.out.println("🔏 Signature valid: " + verified);
        }

        // Integrity check
        if (encData.isIntegrityProtected()) {
            System.out.println("🔐 Integrity check: " + encData.verify());
        }
    }

}