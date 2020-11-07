package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.crypto.DSA;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.ECDSASigner;
import com.distrimind.bouncycastle.crypto.signers.HMacDSAKCalculator;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for the verification of the raw ECDSA signature type using the BC light-weight API.
 */
public class BcTlsECDSAVerifier
    extends BcTlsDSSVerifier
{
    public BcTlsECDSAVerifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new ECDSASigner(new HMacDSAKCalculator(crypto.createDigest(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
