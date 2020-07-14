package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.encodings.PKCS1Encoding;
import com.distrimind.bouncycastle.crypto.engines.RSABlindedEngine;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bouncycastle.crypto.params.RSAKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.GenericSigner;
import com.distrimind.bouncycastle.crypto.signers.RSADigestSigner;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.HashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.TlsUtils;

/**
 * Operator supporting the generation of RSASSA-PKCS1-v1_5 signatures using the BC light-weight API.
 */
public class BcTlsRSASigner
    extends BcTlsSigner
{
    private final RSAKeyParameters publicKey;

    public BcTlsRSASigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, RSAKeyParameters publicKey)
    {
        super(crypto, privateKey);

        this.publicKey = publicKey;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        Digest nullDigest = crypto.createDigest(HashAlgorithm.none);

        Signer signer;
        if (algorithm != null)
        {
            if (algorithm.getSignature() != SignatureAlgorithm.rsa)
            {
                throw new IllegalStateException();
            }

            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
            signer = new RSADigestSigner(nullDigest, TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
        }
        else
        {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
            signer = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), nullDigest);
        }
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));
        signer.update(hash, 0, hash.length);
        try
        {
            byte[] signature = signer.generateSignature();

            signer.init(false, publicKey);
            signer.update(hash, 0, hash.length);

            if (signer.verifySignature(signature))
            {
                return signature;
            }
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
