package org.example;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import java.time.Instant;
import java.util.Date;

public class PGPKeyRingWithSubkey {

    /**
     * Generates an OpenPGP keyring containing:
     * - A primary RSA key (for certification and signing)
     * - An RSA encryption subkey
     * Both are self-signed and printed in ASCII-armored format.
     *
     * @param signingKeyPair    The RSA key pair for the main (signing) key
     * @param encryptionKeyPair The RSA key pair for the subkey (encryption)
     * @param userId            User ID (e.g., "Alice Example <alice@example.com>")
     * @param creationDate      Creation date for both keys
     */
    public static void generatePGPKeyRing(
            KeyPair signingKeyPair,
            KeyPair encryptionKeyPair,
            String userId,
            Date creationDate
    ) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        // === Create PGP key pairs ===
        PGPKeyPair pgpSignKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_SIGN, signingKeyPair, creationDate);

        // === Create a digest calculator for checksums and signatures ===
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
                .build()
                .get(HashAlgorithmTags.SHA1);

        // === Define content signer (for self-certification) ===
        PGPContentSignerBuilder contentSignerBuilder =
                new CustomContentSignerBuilder(
                        PublicKeyAlgorithmTags.RSA_SIGN,
                        HashAlgorithmTags.SHA256,
                        signingKeyPair.getPrivate());


        // === Define hashed subpackets (capabilities, algorithms, etc.) ===
        PGPSignatureSubpacketGenerator hashedSubPackets = new PGPSignatureSubpacketGenerator();
        hashedSubPackets.setIssuerFingerprint(false, pgpSignKeyPair.getPublicKey());
        hashedSubPackets.setKeyFlags(false,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
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
        hashedSubPackets.setPreferredCompressionAlgorithms(false, new int[]{CompressionAlgorithmTags.ZIP});

        // === Create the key ring generator ===
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpSignKeyPair,
                userId,
                sha1Calc,
                hashedSubPackets.generate(),
                null,
                contentSignerBuilder,
                null
        );

        // === Add encryption subkey, if available ===

        if (encryptionKeyPair != null) {
            PGPKeyPair pgpEncKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_ENCRYPT, encryptionKeyPair, creationDate);

            PGPSignatureSubpacketGenerator subkeySubPackets = new PGPSignatureSubpacketGenerator();
            subkeySubPackets.setIssuerFingerprint(false, pgpSignKeyPair.getPublicKey());
            subkeySubPackets.setKeyExpirationTime(false, 10 * 365 * 24 * 60 * 60);
            subkeySubPackets.setKeyFlags(false,
                    KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

            keyRingGen.addSubKey(
                    pgpEncKeyPair,
                    subkeySubPackets.generate(),
                    null
            );
        }

        // === Generate keyrings ===
        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        // === Output armored public and secret keys ===
        try (OutputStream out = new ArmoredOutputStream(System.out)) {
            pubRing.encode(out);
        }

//        System.out.println("\n\n-----BEGIN PGP PRIVATE KEY BLOCK-----");
//        try (OutputStream out = new ArmoredOutputStream(System.out)) {
//            secRing.encode(out);
//        }
        System.out.println();
    }

    // === Example usage ===
    public static void main(String[] args) throws Exception {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(4096);

        //KeyPair signingKeyPair = kpg.generateKeyPair();
        KeyPair signingKeyPair = PGPKeyConversionUtils.pemFileToKeyPair(Files.readString(Path.of("src/test/resources/org/example/bob-private.pem")));
        KeyPair actualKeyPair = new KeyPair(signingKeyPair.getPublic(), null);
//        KeyPair encryptionKeyPair = kpg.generateKeyPair();

        String userId = "Bob Babbage <bob@openpgp.example>";
        Date creationDate = Date.from(Instant.parse("2019-10-15T10:18:26Z"));

        generatePGPKeyRing(signingKeyPair, null, userId, creationDate);
        //generatePGPKeyRing(signingKeyPair, encryptionKeyPair, userId, creationDate);
    }
}
