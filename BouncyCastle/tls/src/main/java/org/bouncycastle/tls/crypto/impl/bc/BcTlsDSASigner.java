package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.bccrypto.DSA;
import org.bouncycastle.bccrypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.bccrypto.signers.DSASigner;
import org.bouncycastle.bccrypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;

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

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(crypto.createDigest(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
