package org.bouncycastle.bccrypto.agreement;

import org.bouncycastle.bccrypto.CipherParameters;
import org.bouncycastle.bccrypto.RawAgreement;
import org.bouncycastle.bccrypto.params.X448PrivateKeyParameters;
import org.bouncycastle.bccrypto.params.X448PublicKeyParameters;

public final class X448Agreement
    implements RawAgreement
{
    private X448PrivateKeyParameters privateKey;

    public void init(CipherParameters parameters)
    {
        this.privateKey = (X448PrivateKeyParameters)parameters;
    }

    public int getAgreementSize()
    {
        return X448PrivateKeyParameters.SECRET_SIZE;
    }

    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
    {
        privateKey.generateSecret((X448PublicKeyParameters)publicKey, buf, off);
    }
}
