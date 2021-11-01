package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.crypto.DSA;
import com.distrimind.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.DSASigner;
import com.distrimind.bouncycastle.crypto.signers.HMacDSAKCalculator;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for generation of the raw DSA signature type using the BC light-weight API.
 */
public class BcTlsDSASigner
    extends BcTlsDSSSigner
{
    public BcTlsDSASigner(BcTlsCrypto crypto, DSAPrivateKeyParameters privateKey)
    {
        super(crypto, privateKey);
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
