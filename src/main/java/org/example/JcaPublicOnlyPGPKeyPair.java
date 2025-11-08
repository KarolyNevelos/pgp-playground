package org.example;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;

import java.security.PublicKey;
import java.util.Date;

public class JcaPublicOnlyPGPKeyPair extends PGPKeyPair {

    public JcaPublicOnlyPGPKeyPair(int algorithm, PublicKey publicKey, Date date) throws PGPException {
        this.pub = getPublicKey(algorithm, publicKey, date);
        this.priv = null;
    }

    private static PGPPublicKey getPublicKey(int algorithm, PublicKey pubKey, Date date)
            throws PGPException
    {
        return  new JcaPGPKeyConverter().getPGPPublicKey(algorithm, pubKey, date);
    }

}
