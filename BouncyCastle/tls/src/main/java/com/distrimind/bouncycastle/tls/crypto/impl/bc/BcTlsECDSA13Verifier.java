package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.crypto.DSA;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.digests.NullDigest;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.DSADigestSigner;
import com.distrimind.bouncycastle.crypto.signers.ECDSASigner;
import com.distrimind.bouncycastle.crypto.signers.HMacDSAKCalculator;
import com.distrimind.bouncycastle.tls.DigitallySigned;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureScheme;

/**
 * Implementation class for verification of ECDSA signatures in TLS 1.3+ using the BC light-weight API.
 */
public class BcTlsECDSA13Verifier
    extends BcTlsVerifier
{
    private final int signatureScheme;

    public BcTlsECDSA13Verifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey, int signatureScheme)
    {
        super(crypto, publicKey);

        if (!SignatureScheme.isECDSA(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.signatureScheme = signatureScheme;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        DSA dsa = new ECDSASigner(new HMacDSAKCalculator(crypto.createDigest(cryptoHashAlgorithm)));

        Signer signer = new DSADigestSigner(dsa, new NullDigest());
        signer.init(false, publicKey);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(signature.getSignature());
    }
}
