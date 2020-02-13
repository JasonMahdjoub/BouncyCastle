package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.bccrypto.DSA;
import org.bouncycastle.bccrypto.params.DSAPublicKeyParameters;
import org.bouncycastle.bccrypto.signers.DSASigner;
import org.bouncycastle.bccrypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;

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

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(crypto.createDigest(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
