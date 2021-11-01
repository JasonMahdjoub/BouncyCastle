package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.crypto.DSA;
import com.distrimind.bouncycastle.crypto.params.DSAPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.DSASigner;
import com.distrimind.bouncycastle.crypto.signers.HMacDSAKCalculator;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for the verification of the raw DSA signature type using the BC light-weight API.
 */
public class BcTlsDSAVerifier
    extends BcTlsDSSVerifier
{
    public BcTlsDSAVerifier(BcTlsCrypto crypto, DSAPublicKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    protected DSA createDSAImpl(int cryptoHashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(crypto.createDigest(cryptoHashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
