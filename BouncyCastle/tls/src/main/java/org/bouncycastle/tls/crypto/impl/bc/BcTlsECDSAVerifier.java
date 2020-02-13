package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.bccrypto.DSA;
import org.bouncycastle.bccrypto.params.ECPublicKeyParameters;
import org.bouncycastle.bccrypto.signers.ECDSASigner;
import org.bouncycastle.bccrypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;

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
