package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.digests.NullDigest;
import com.distrimind.bouncycastle.crypto.encodings.PKCS1Encoding;
import com.distrimind.bouncycastle.crypto.engines.RSABlindedEngine;
import com.distrimind.bouncycastle.crypto.params.RSAKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.GenericSigner;
import com.distrimind.bouncycastle.crypto.signers.RSADigestSigner;
import com.distrimind.bouncycastle.tls.DigitallySigned;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.TlsUtils;

/**
 * Operator supporting the verification of RSASSA-PKCS1-v1_5 signatures using the BC light-weight API.
 */
public class BcTlsRSAVerifier
    extends BcTlsVerifier
{
    public BcTlsRSAVerifier(BcTlsCrypto crypto, RSAKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash)
    {
        Digest nullDigest = new NullDigest();

        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        Signer signer;
        if (algorithm != null)
        {
            if (algorithm.getSignature() != SignatureAlgorithm.rsa)
            {
                throw new IllegalStateException("Invalid algorithm: " + algorithm);
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
        signer.init(false, publicKey);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(signedParams.getSignature());
    }
}
