package com.distrimind.bouncycastle.openpgp.operator.jcajce;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import com.distrimind.bouncycastle.openpgp.PGPAlgorithmParameters;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPKeyPair;
import com.distrimind.bouncycastle.openpgp.PGPPrivateKey;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;

/**
 * A PGP key pair class that is constructed from JCA/JCE key pairs.
 */
public class JcaPGPKeyPair
    extends PGPKeyPair
{
    private static PGPPublicKey getPublicKey(int algorithm, PublicKey pubKey, Date date)
        throws PGPException
    {
        return  new JcaPGPKeyConverter().getPGPPublicKey(algorithm, pubKey, date);
    }

    private static PGPPublicKey getPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, Date date)
        throws PGPException
    {
        return  new JcaPGPKeyConverter().getPGPPublicKey(algorithm, algorithmParameters, pubKey, date);
    }

    private static PGPPrivateKey getPrivateKey(PGPPublicKey pub, PrivateKey privKey)
        throws PGPException
    {
        return new JcaPGPKeyConverter().getPGPPrivateKey(pub, privKey);
    }

    /**
     * Construct PGP key pair from a JCA/JCE key pair.
     *
     * @param algorithm the PGP algorithm the key is for.
     * @param keyPair  the public/private key pair to convert.
     * @param date the creation date to associate with the key pair.
     * @throws PGPException if conversion fails.
     */
    public JcaPGPKeyPair(int algorithm, KeyPair keyPair, Date date)
        throws PGPException
    {
        this.pub = getPublicKey(algorithm, keyPair.getPublic(), date);
        this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
    }

    /**
     * Construct PGP key pair from a JCA/JCE key pair.
     *
     * @param algorithm the PGP algorithm the key is for.
     * @param parameters additional parameters to be stored against the public key.
     * @param keyPair  the public/private key pair to convert.
     * @param date the creation date to associate with the key pair.
     * @throws PGPException if conversion fails.
     */
    public JcaPGPKeyPair(int algorithm, PGPAlgorithmParameters parameters, KeyPair keyPair, Date date)
        throws PGPException
    {
        this.pub = getPublicKey(algorithm, parameters, keyPair.getPublic(), date);
        this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
    }
}
