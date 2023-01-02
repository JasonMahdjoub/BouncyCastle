package com.distrimind.bouncycastle.its;

import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;

public class ITSPublicVerificationKey
{
    protected final PublicVerificationKey verificationKey;

    public ITSPublicVerificationKey(PublicVerificationKey encryptionKey)
    {
        this.verificationKey = encryptionKey;
    }

    public PublicVerificationKey toASN1Structure()
    {
        return verificationKey;
    }
}
