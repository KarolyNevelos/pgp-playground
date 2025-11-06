package org.example;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class PgpMessageReader {

    private final PublicKeyDataDecryptorFactory dataDecryptorFactory;
    private final PGPPublicKey signingKey;

    public static PgpMessageReader createStandard(PGPPublicKey senderPublicKey, PGPPrivateKey decryptorKey){
        return new PgpMessageReader(new BcPublicKeyDataDecryptorFactory(decryptorKey), senderPublicKey);
    }

    public static PgpMessageReader createCustom(PGPPublicKey senderPublicKey, String pemFilePath) throws IOException {
        return new PgpMessageReader(new CustomPrivateKeyDecryptor(pemFilePath).buildDecryptorFactory(), senderPublicKey);
    }

    public PgpMessageReader(PublicKeyDataDecryptorFactory dataDecryptorFactory, PGPPublicKey signingKey){
        this.dataDecryptorFactory = dataDecryptorFactory;
        this.signingKey = signingKey;
    }

    public MessageResult decryptAndVerify(InputStream in)
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
        InputStream clear = encData.getDataStream(dataDecryptorFactory);

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

            // Verify trailing signature
            PGPSignature signature = signatureList.get(0);
            boolean verified = onePass.verify(signature);

            // Integrity check
            if (!encData.isIntegrityProtected()) {
                throw new IllegalStateException("Encrypted data is not integrity protected");
            }

            return new MessageResult(plaintext, verified, encData.verify());
        }

    }

    static class MessageResult {

        private String message;
        private boolean verified;
        private boolean integrityChecked;

        public MessageResult(String message, boolean verified, boolean integrityChecked) {
            this.message = message;
            this.verified = verified;
            this.integrityChecked = integrityChecked;
        }

        public String getMessage() {
            return message;
        }

        public boolean isVerified() {
            return verified;
        }

        public boolean isIntegrityChecked() {
            return integrityChecked;
        }
    }
}