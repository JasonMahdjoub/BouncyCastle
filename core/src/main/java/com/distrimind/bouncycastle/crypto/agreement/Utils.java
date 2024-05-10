package com.distrimind.bouncycastle.crypto.agreement;

import com.distrimind.bouncycastle.crypto.CryptoServiceProperties;
import com.distrimind.bouncycastle.crypto.CryptoServicePurpose;
import com.distrimind.bouncycastle.crypto.constraints.ConstraintUtils;
import com.distrimind.bouncycastle.crypto.constraints.DefaultServiceProperties;
import com.distrimind.bouncycastle.crypto.params.DHKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECKeyParameters;
import com.distrimind.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.X448PrivateKeyParameters;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, ECKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getCurve()), k, CryptoServicePurpose.AGREEMENT);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, DHKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k, CryptoServicePurpose.AGREEMENT);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, X448PrivateKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, 224, k, CryptoServicePurpose.AGREEMENT);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, X25519PrivateKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, 128, k, CryptoServicePurpose.AGREEMENT);
    }
}
