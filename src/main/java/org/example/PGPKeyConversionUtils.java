package org.example;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

/**
 * Utility class for converting RSA key formats between
 * OpenPGP (ASCII-armored) and standard PEM encoding.
 */
public class PGPKeyConversionUtils {

    /**
     * Converts an ASCII-armored OpenPGP private key block
     * ("-----BEGIN PGP PRIVATE KEY BLOCK-----") to a PEM-encoded
     * private key ("-----BEGIN PRIVATE KEY-----").
     */
    public static String pgpPrivateToPem(String pgpPrivateKey) throws Exception {
        PGPSecretKeyRing secretKeyRing = readSecretKeyRing(pgpPrivateKey);
        PGPPrivateKey pgpPrivateKeyObj = extractPrivateKey(secretKeyRing);
        PrivateKey privateKey = convertToJavaPrivateKey(pgpPrivateKeyObj);

        StringWriter out = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(out)) {
            pemWriter.writeObject(new JcaPKCS8Generator(privateKey, null));
        }
        return out.toString();
    }

    /**
     * Converts a PEM-encoded private key ("-----BEGIN PRIVATE KEY-----")
     * to an ASCII-armored OpenPGP private key block.
     */
    public static String pemPrivateToPgp(String pemPrivateKey, Date date, String identity) throws Exception {

        // Wrap into PGP keys
        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(
                PGPPublicKey.RSA_GENERAL,
                pemFileToKeyPair(pemPrivateKey),
                date
        );

        // Create digest calculator (for metadata checksums)
        PGPDigestCalculator sha1Calc =
                new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        // Create unencrypted PGP key ring generator (pass null encryptor)
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpKeyPair,
                identity,
                sha1Calc,
                null,   // no attributes
                null,   // no subpackets
                new JcaPGPContentSignerBuilder(
                        pgpKeyPair.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA256
                ),
                null // <-- no secret key encryption
        );

        // Generate armored output
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ArmoredOutputStream aos = new ArmoredOutputStream(baos)) {
            keyRingGen.generateSecretKeyRing().encode(aos);
        }

        return baos.toString();
    }

    public static KeyPair pemFileToKeyPair(String pemPrivateKey) throws Exception {
        PemObject pem = readPemObject(pemPrivateKey);
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(pem.getContent()));

        // Derive PublicKey
        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.RSAPublicKeySpec(
                        ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getModulus(),
                        ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getPublicExponent()
                ));
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Converts an ASCII-armored OpenPGP public key block
     * ("-----BEGIN PGP PUBLIC KEY BLOCK-----") to a PEM-encoded
     * public key ("-----BEGIN PUBLIC KEY-----").
     */
    public static String pgpPublicToPem(String pgpPublicKey) throws Exception {
        PGPPublicKeyRing publicKeyRing = readPublicKeyRing(pgpPublicKey);
        PGPPublicKey pgpPublicKeyObj = publicKeyRing.getPublicKey();
        PublicKey publicKey = convertToJavaPublicKey(pgpPublicKeyObj);

        StringWriter out = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(out)) {
            pemWriter.writeObject(publicKey);
        }
        return out.toString();
    }

    /**
     * Converts a PEM-encoded private key ("-----BEGIN PRIVATE KEY-----")
     * to an ASCII-armored OpenPGP public key block.
     */
    public static String pemPublicToPgp(String pemPrivateKey, Date date, String identity) throws Exception {
        // Wrap into PGP keys
        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(
                PGPPublicKey.RSA_GENERAL,
                pemFileToKeyPair(pemPrivateKey),
                date
        );

        // Create digest calculator (for metadata checksums)
        PGPDigestCalculator sha1Calc =
                new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        // Create unencrypted PGP key ring generator (pass null encryptor)
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpKeyPair,
                identity,
                sha1Calc,
                null,   // no attributes
                null,   // no subpackets
                new JcaPGPContentSignerBuilder(
                        pgpKeyPair.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA256
                ),
                null // <-- no secret key encryption
        );

        // Generate armored output
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ArmoredOutputStream aos = new ArmoredOutputStream(baos)) {
            keyRingGen.generatePublicKeyRing().encode(aos);
        }

        return baos.toString();
    }

    // ------------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------------

    private static PGPSecretKeyRing readSecretKeyRing(String pgpPrivateKey) throws IOException, PGPException {
        try (InputStream in = new ArmoredInputStream(new ByteArrayInputStream(pgpPrivateKey.getBytes()))) {
            return new PGPSecretKeyRing(in, new JcaKeyFingerprintCalculator());
        }
    }

    private static PGPPublicKeyRing readPublicKeyRing(String pgpPublicKey) throws IOException {
        try (InputStream in = new ArmoredInputStream(new ByteArrayInputStream(pgpPublicKey.getBytes()))) {
            return new PGPPublicKeyRing(in, new JcaKeyFingerprintCalculator());
        }
    }

    private static PGPPrivateKey extractPrivateKey(PGPSecretKeyRing secretKeyRing) throws PGPException {
        PGPSecretKey secretKey = secretKeyRing.getSecretKey();
        return secretKey.extractPrivateKey(null); // no passphrase
    }

    private static PrivateKey convertToJavaPrivateKey(PGPPrivateKey pgpPrivateKey) throws Exception {
        RSASecretBCPGKey rsaPriv = (RSASecretBCPGKey) pgpPrivateKey.getPrivateKeyDataPacket();

        BigInteger n = rsaPriv.getModulus();
        BigInteger d = rsaPriv.getPrivateExponent();
        BigInteger p = rsaPriv.getPrimeP();
        BigInteger q = rsaPriv.getPrimeQ();
        BigInteger u = rsaPriv.getPrimeExponentP(); // sometimes available
        BigInteger e = ((RSAPublicBCPGKey) pgpPrivateKey.getPublicKeyPacket().getKey()).getPublicExponent();

        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
                n, e, d, p, q,
                d.mod(p.subtract(BigInteger.ONE)),  // dP
                d.mod(q.subtract(BigInteger.ONE)),  // dQ
                q.modInverse(p)                     // qInv
        );
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static PublicKey convertToJavaPublicKey(PGPPublicKey pgpPublicKey) throws Exception {
        RSAPublicBCPGKey rsaPublic = (RSAPublicBCPGKey) pgpPublicKey.getPublicKeyPacket().getKey();

        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                rsaPublic.getModulus(),
                rsaPublic.getPublicExponent()
        );

        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static PemObject readPemObject(String pemString) throws IOException {
        try (PemReader reader = new PemReader(new StringReader(pemString))) {
            return reader.readPemObject();
        }
    }
}
