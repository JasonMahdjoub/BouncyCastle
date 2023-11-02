package com.distrimind.bouncycastle.crypto.signers;

import com.distrimind.bouncycastle.crypto.constraints.ConstraintUtils;
import com.distrimind.bouncycastle.crypto.constraints.DefaultServiceProperties;
import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.CryptoServiceProperties;
import com.distrimind.bouncycastle.crypto.CryptoServicePurpose;
import com.distrimind.bouncycastle.crypto.params.DSAKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECKeyParameters;
import com.distrimind.bouncycastle.crypto.params.GOST3410KeyParameters;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, DSAKeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, GOST3410KeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, ECKeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getCurve()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, int bitsOfSecurity, CipherParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity, k, getPurpose(forSigning));
    }

    static CryptoServicePurpose getPurpose(boolean forSigning)
    {
        return forSigning ? CryptoServicePurpose.SIGNING : CryptoServicePurpose.VERIFYING;
    }
}
