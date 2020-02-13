package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.bccrypto.CryptoException;
import org.bouncycastle.bccrypto.Digest;
import org.bouncycastle.bccrypto.Signer;
import org.bouncycastle.bccrypto.encodings.PKCS1Encoding;
import org.bouncycastle.bccrypto.engines.RSABlindedEngine;
import org.bouncycastle.bccrypto.params.ParametersWithRandom;
import org.bouncycastle.bccrypto.params.RSAKeyParameters;
import org.bouncycastle.bccrypto.signers.GenericSigner;
import org.bouncycastle.bccrypto.signers.RSADigestSigner;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;

/**
 * Operator supporting the generation of RSASSA-PKCS1-v1_5 signatures using the BC light-weight API.
 */
public class BcTlsRSASigner
    extends BcTlsSigner
{
    public BcTlsRSASigner(BcTlsCrypto crypto, RSAKeyParameters privateKey)
    {
        super(crypto, privateKey);
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
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
