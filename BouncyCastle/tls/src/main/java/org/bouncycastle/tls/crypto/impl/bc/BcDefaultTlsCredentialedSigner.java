package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.RSAKeyParameters;
import com.distrimind.bouncycastle.tls.Certificate;
import com.distrimind.bouncycastle.tls.DefaultTlsCredentialedSigner;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.crypto.TlsCryptoParameters;
import com.distrimind.bouncycastle.tls.crypto.TlsSigner;

/**
 * Credentialed class for generating signatures based on the use of primitives from the BC light-weight API.
 */
public class BcDefaultTlsCredentialedSigner
    extends DefaultTlsCredentialedSigner
{
    private static BcTlsCertificate getEndEntity(BcTlsCrypto crypto, Certificate certificate) throws IOException
    {
        if (certificate == null || certificate.isEmpty())
        {
            throw new IllegalArgumentException("No certificate");
        }

        return BcTlsCertificate.convert(crypto, certificate.getCertificateAt(0));
    }

    private static TlsSigner makeSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate,
        SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        TlsSigner signer;
        if (privateKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters privKeyRSA = (RSAKeyParameters)privateKey;

            if (signatureAndHashAlgorithm != null)
            {
                short signatureAlgorithm = signatureAndHashAlgorithm.getSignature();
                switch (signatureAlgorithm)
                {
                case SignatureAlgorithm.rsa_pss_pss_sha256:
                case SignatureAlgorithm.rsa_pss_pss_sha384:
                case SignatureAlgorithm.rsa_pss_pss_sha512:
                case SignatureAlgorithm.rsa_pss_rsae_sha256:
                case SignatureAlgorithm.rsa_pss_rsae_sha384:
                case SignatureAlgorithm.rsa_pss_rsae_sha512:
                    return new BcTlsRSAPSSSigner(crypto, privKeyRSA, signatureAlgorithm);
                }
            }

            RSAKeyParameters pubKeyRSA;
            try
            {
                pubKeyRSA = getEndEntity(crypto, certificate).getPubKeyRSA();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }

            signer = new BcTlsRSASigner(crypto, privKeyRSA, pubKeyRSA);
        }
        else if (privateKey instanceof DSAPrivateKeyParameters)
        {
            signer = new BcTlsDSASigner(crypto, (DSAPrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            signer = new BcTlsECDSASigner(crypto, (ECPrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof Ed25519PrivateKeyParameters)
        {
            signer = new BcTlsEd25519Signer(crypto, (Ed25519PrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof Ed448PrivateKeyParameters)
        {
            signer = new BcTlsEd448Signer(crypto, (Ed448PrivateKeyParameters)privateKey);
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        return signer;
    }

    public BcDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, BcTlsCrypto crypto,
        AsymmetricKeyParameter privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(cryptoParams, makeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate,
            signatureAndHashAlgorithm);
    }
}
