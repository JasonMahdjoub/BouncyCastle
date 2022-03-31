package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.distrimind.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.crypto.TlsAgreement;
import com.distrimind.bouncycastle.tls.crypto.TlsCryptoException;
import com.distrimind.bouncycastle.tls.crypto.TlsECDomain;
import com.distrimind.bouncycastle.util.Arrays;

public class JceX25519Domain implements TlsECDomain
{
    protected final JcaTlsCrypto crypto;

    public JceX25519Domain(JcaTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public JceTlsSecret calculateECDHAgreement(PrivateKey privateKey, PublicKey publicKey)
        throws IOException
    {
        try
        {
            byte[] secret = crypto.calculateKeyAgreement("X25519", privateKey, publicKey, "TlsPremasterSecret");

            if (secret == null || secret.length != 32)
            {
                throw new TlsCryptoException("invalid secret calculated");
            }
            if (Arrays.areAllZeroes(secret, 0, secret.length))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            return crypto.adoptLocalSecret(secret);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    public TlsAgreement createECDH()
    {
        return new JceX25519(this);
    }

    public PublicKey decodePublicKey(byte[] encoding) throws IOException
    {
        return XDHUtil.decodePublicKey(crypto, "X25519", EdECObjectIdentifiers.id_X25519, encoding);
    }

    public byte[] encodePublicKey(PublicKey publicKey) throws IOException
    {
        return XDHUtil.encodePublicKey(publicKey);
    }

    public KeyPair generateKeyPair()
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("X25519");
            keyPairGenerator.initialize(255, crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }
}
