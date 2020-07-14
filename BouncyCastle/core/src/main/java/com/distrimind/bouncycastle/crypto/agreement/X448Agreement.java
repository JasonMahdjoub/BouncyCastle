package com.distrimind.bouncycastle.crypto.agreement;

import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.RawAgreement;
import com.distrimind.bouncycastle.crypto.params.X448PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.X448PublicKeyParameters;

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
