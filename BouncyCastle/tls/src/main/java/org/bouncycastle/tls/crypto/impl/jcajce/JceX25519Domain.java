package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import com.distrimind.bouncycastle.asn1.ASN1Encoding;
import com.distrimind.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
        try
        {
            AlgorithmIdentifier algID = new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519);
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algID, encoding);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER));

            KeyFactory kf = crypto.getHelper().createKeyFactory("X25519");
            return kf.generatePublic(keySpec);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public byte[] encodePublicKey(PublicKey publicKey) throws IOException
    {
        try
        {
            if ("X.509".equals(publicKey.getFormat()))
            {
                SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
                return spki.getPublicKeyData().getOctets();
            }
        }
        catch (Exception e)
        {
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
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
