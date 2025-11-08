package org.example;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.function.Function;

public class ExternalPGPPublicKeyGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static PGPPublicKeyRing generate(
            RSAPublicKey masterPublicKey,
            RSAPublicKey subPublicKeyOpt,
            String userId,
            Date creationTime,
            Function<byte[], byte[]> externalSigner
    ) throws Exception {

        // --- 1. Convert master public key ---
        int keyAlgorithm = PublicKeyAlgorithmTags.RSA_GENERAL;
        int hashAlgorithm = HashAlgorithmTags.SHA256;

        RSAPublicBCPGKey masterRsa = new RSAPublicBCPGKey(
                masterPublicKey.getModulus(),
                masterPublicKey.getPublicExponent()
        );
        PGPPublicKey masterKey = new PGPPublicKey(
                new PublicKeyPacket(PublicKeyPacket.VERSION_4, keyAlgorithm, creationTime, masterRsa),
                new JcaKeyFingerprintCalculator()
        );

        // --- 2. External signer builder ---
        PGPContentSignerBuilder signerBuilder = new ExternalPGPContentSignerBuilder(
                keyAlgorithm, hashAlgorithm, externalSigner, masterKey.getKeyID()
        );

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(signerBuilder);
        sigGen.init(PGPSignature.POSITIVE_CERTIFICATION, null);

        // --- 3. Self-signature over User ID ---
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        spGen.setSignatureCreationTime(false, creationTime);
        spGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        sigGen.setHashedSubpackets(spGen.generate());

        PGPSignature selfSig = sigGen.generateCertification(userId, masterKey);
        PGPPublicKey signedMasterKey = PGPPublicKey.addCertification(masterKey, userId, selfSig);

        // --- 4. Optional subkey handling ---
        if (subPublicKeyOpt != null) {
            RSAPublicBCPGKey subRsa = new RSAPublicBCPGKey(
                    subPublicKeyOpt.getModulus(),
                    subPublicKeyOpt.getPublicExponent()
            );

            PGPPublicKey subKey = new PGPPublicKey(
                    new PublicSubkeyPacket(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.RSA_GENERAL, creationTime, subRsa),
                    new JcaKeyFingerprintCalculator()
            );

            PGPSignatureGenerator bindGen = new PGPSignatureGenerator(signerBuilder);
            bindGen.init(PGPSignature.SUBKEY_BINDING, null);

            PGPSignatureSubpacketGenerator bindSpGen = new PGPSignatureSubpacketGenerator();
            bindSpGen.setSignatureCreationTime(false, creationTime);
            bindSpGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
            bindGen.setHashedSubpackets(bindSpGen.generate());

            PGPSignature bindingSig = bindGen.generateCertification(signedMasterKey, subKey);
            PGPPublicKey boundSubKey = PGPPublicKey.addCertification(subKey, bindingSig);

            return new PGPPublicKeyRing(Arrays.asList(signedMasterKey, boundSubKey));
        }

        // --- 5. Master key only ---
        return new PGPPublicKeyRing(Arrays.asList(signedMasterKey));
    }
}
