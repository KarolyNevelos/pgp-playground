package org.example;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.operator.PGPContentSigner;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.function.Function;

public class ExternalPGPContentSigner implements PGPContentSigner {

    private final int keyAlgorithm;
    private final int hashAlgorithm;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final Function<byte[], byte[]> externalSigner;
    private final int signatureType;
    private final long keyId;

    public ExternalPGPContentSigner(
            int keyAlgorithm,
            int hashAlgorithm,
            int signatureType,
            long keyId,
            Function<byte[], byte[]> externalSigner) {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.externalSigner = externalSigner;
        this.signatureType = signatureType;
        this.keyId = keyId;
    }

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
        return keyId;
    }

    @Override
    public OutputStream getOutputStream() {
        return buffer;
    }

    @Override
    public byte[] getSignature() {
        byte[] data = buffer.toByteArray();
        return externalSigner.apply(data);
    }

    @Override
    public byte[] getDigest() {
        return digest(buffer.toByteArray(), hashAlgorithm);
    }

    private byte[] digest(byte[] data, int hashAlgorithm) {
        try {
            String algoName = switch (hashAlgorithm) {
                case HashAlgorithmTags.SHA256 -> "SHA-256";
                case HashAlgorithmTags.SHA512 -> "SHA-512";
                default -> throw new IllegalArgumentException("Unsupported hash");
            };
            return MessageDigest.getInstance(algoName).digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
