package org.example;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.function.Function;

public class ExternalPGPPublicKeyGenerator {

    public static PGPPublicKeyRing generate(
            RSAPublicKey rsaPublicKey,
            String userId,
            Date creationTime,
            Function<byte[], byte[]> externalSigner
    ) throws Exception {

        int keyAlgorithm = PublicKeyAlgorithmTags.RSA_GENERAL;
        int hashAlgorithm = HashAlgorithmTags.SHA256;

        BCPGKey signPublicKey = new RSAPublicBCPGKey(
                rsaPublicKey.getModulus(),
                rsaPublicKey.getPublicExponent()
        );

        PublicKeyPacket pubKeyPacket = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                keyAlgorithm,
                creationTime,
                signPublicKey
        );

        PGPPublicKey pgpPublicKey = new PGPPublicKey(pubKeyPacket, new JcaKeyFingerprintCalculator());

        // Step 2: Create a custom signer using your external function
        PGPContentSignerBuilder signerBuilder =
                new ExternalPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm, externalSigner, pgpPublicKey.getKeyID());

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(signerBuilder);

        sigGen.init(PGPSignature.POSITIVE_CERTIFICATION, null);

        // Step 3: Build user ID self-signature
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        spGen.setSignatureCreationTime(false, creationTime);
        spGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        sigGen.setHashedSubpackets(spGen.generate());

        PGPSignature selfSig = sigGen.generateCertification(userId, pgpPublicKey);

        // Step 4: Combine into a PGPPublicKey with self-signature
        PGPPublicKey signedKey = PGPPublicKey.addCertification(pgpPublicKey, userId, selfSig);

        // Step 5: Create a public key ring
        return new PGPPublicKeyRing(java.util.Collections.singletonList(signedKey));
    }

}
