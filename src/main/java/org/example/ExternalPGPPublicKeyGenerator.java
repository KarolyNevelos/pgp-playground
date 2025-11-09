package org.example;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

public class ExternalPGPPublicKeyGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PGPPublicKeyRing generate(
            String userId, Date creationTime, Function<byte[], byte[]> externalSigner,
            RSAPublicKey masterPublicKey, int masterKeyFlags,
            RSAPublicKey subPublicKey, int subKeyFlags
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
                keyAlgorithm, hashAlgorithm, masterKey.getKeyID(), externalSigner
        );

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(signerBuilder);
        sigGen.init(PGPSignature.POSITIVE_CERTIFICATION, null);

        // --- 3. Self-signature over User ID ---
        PGPSignatureSubpacketGenerator hashedSubPackets = new PGPSignatureSubpacketGenerator();
        hashedSubPackets.setIssuerFingerprint(false, masterKey);
        hashedSubPackets.setSignatureCreationTime(false, creationTime);
        hashedSubPackets.setKeyFlags(false, masterKeyFlags);
        hashedSubPackets.setPreferredSymmetricAlgorithms(false,
                new int[]{
                        SymmetricKeyAlgorithmTags.AES_256,
                        SymmetricKeyAlgorithmTags.AES_192,
                        SymmetricKeyAlgorithmTags.AES_128
                });
        hashedSubPackets.setPreferredHashAlgorithms(false,
                new int[]{
                        HashAlgorithmTags.SHA512,
                        HashAlgorithmTags.SHA384,
                        HashAlgorithmTags.SHA256
                });
        hashedSubPackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        hashedSubPackets.setKeyExpirationTime(false, 10 * 365 * 24 * 60 * 60);
        hashedSubPackets.setPreferredCompressionAlgorithms(false, new int[]{ CompressionAlgorithmTags.ZIP });

        sigGen.setHashedSubpackets(hashedSubPackets.generate());

        PGPSignature selfSig = sigGen.generateCertification(userId, masterKey);
        PGPPublicKey signedMasterKey = PGPPublicKey.addCertification(masterKey, userId, selfSig);

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(signedMasterKey);
        // --- 4. Optional subkey handling ---
        if (subPublicKey != null) {
            RSAPublicBCPGKey subRsa = new RSAPublicBCPGKey(
                    subPublicKey.getModulus(),
                    subPublicKey.getPublicExponent()
            );

            PGPPublicKey subKey = new PGPPublicKey(
                    new PublicSubkeyPacket(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.RSA_GENERAL, creationTime, subRsa),
                    new JcaKeyFingerprintCalculator()
            );

            PGPSignatureGenerator bindGen = new PGPSignatureGenerator(signerBuilder);
            bindGen.init(PGPSignature.SUBKEY_BINDING, null);

            PGPSignatureSubpacketGenerator subkeySubPackets = new PGPSignatureSubpacketGenerator();
            subkeySubPackets.setSignatureCreationTime(false, creationTime);
            subkeySubPackets.setKeyFlags(false, subKeyFlags);
            subkeySubPackets.setIssuerFingerprint(false, masterKey);
            subkeySubPackets.setKeyExpirationTime(false, 10 * 365 * 24 * 60 * 60);
            bindGen.setHashedSubpackets(subkeySubPackets.generate());

            PGPSignature bindingSig = bindGen.generateCertification(signedMasterKey, subKey);
            PGPPublicKey boundSubKey = PGPPublicKey.addCertification(subKey, bindingSig);

            keys.add(boundSubKey);
        }

        return new PGPPublicKeyRing(keys);
    }
}
