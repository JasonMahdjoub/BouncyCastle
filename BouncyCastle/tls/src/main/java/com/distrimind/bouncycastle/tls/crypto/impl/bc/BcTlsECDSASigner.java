package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.crypto.DSA;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.ECDSASigner;
import com.distrimind.bouncycastle.crypto.signers.HMacDSAKCalculator;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for generation of the raw ECDSA signature type using the BC light-weight API.
 */
public class BcTlsECDSASigner
    extends BcTlsDSSSigner
{
    public BcTlsECDSASigner(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey)
    {
        super(crypto, privateKey);
    }

    protected DSA createDSAImpl(int cryptoHashAlgorithm)
    {
        return new ECDSASigner(new HMacDSAKCalculator(crypto.createDigest(cryptoHashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
