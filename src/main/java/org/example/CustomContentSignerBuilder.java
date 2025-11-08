package org.example;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Date;

/**
 * Custom signature generator using a PKCS#8 private key.
 * This replaces the default Bouncy Castle PGPSignatureGenerator during PGP signing.
 */
public class CustomContentSignerBuilder implements PGPContentSignerBuilder {

    private BcPGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
    private final PrivateKey privateKey;
    private final int keyAlgorithm;
    private final int hashAlgorithm;

    /**
     * Construct from a PKCS#8 PEM string.
     */
    public CustomContentSignerBuilder(int keyAlgorithm, int hashAlgorithm, String pemFilePath) throws Exception {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        try (PEMParser parser = new PEMParser(new FileReader(pemFilePath))) {
            Object obj = parser.readObject();
            if (!(obj instanceof PrivateKeyInfo pkInfo)) {
                throw new IllegalArgumentException("Not a PKCS#8 private key file");
            }
            this.privateKey = new JcaPEMKeyConverter().getPrivateKey(pkInfo);
        }
    }

    public CustomContentSignerBuilder(int keyAlgorithm, int hashAlgorithm, PrivateKey privateKey) {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.privateKey = privateKey;
    }

    @Override
    public PGPContentSigner build(int signatureType, PGPPrivateKey pgpPrivateKey) throws PGPException {

        final Signature signer;
        final PGPDigestCalculator digestCalculator = digestCalculatorProvider.get(hashAlgorithm);
        try {
            signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new PGPContentSigner() {

            @Override
            public int getType() {
                return signatureType;
            }

            @Override
            public int getHashAlgorithm() {
                return hashAlgorithm;
            }

            @Override
            public int getKeyAlgorithm() {
                return keyAlgorithm;
            }

            @Override
            public long getKeyID() {
                try {
                    return KeyIdCalculator.getKeyId(privateKey, Date.from(Instant.parse("2019-10-15T10:18:26Z")), keyAlgorithm);
                } catch (IOException | PGPException e) {
                    throw new RuntimeException(e);
                }
            }

            public OutputStream getOutputStream() {
                return new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        try {
                            signer.update((byte) b);
                        } catch (SignatureException e) {
                            throw new IOException(e);
                        }
                    }

                    @Override
                    public void write(byte[] b, int off, int len) throws IOException {
                        try {
                            signer.update(b, off, len);
                        } catch (SignatureException e) {
                            throw new IOException(e);
                        }
                    }
                };
            }

            @Override
            public byte[] getSignature() {
                try {
                    return signer.sign();
                } catch (SignatureException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public byte[] getDigest() {
                return digestCalculator.getDigest();
            }

        };
    }

}
