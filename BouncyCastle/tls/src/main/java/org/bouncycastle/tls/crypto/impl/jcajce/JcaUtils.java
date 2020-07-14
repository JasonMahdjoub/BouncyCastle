package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.security.Provider;
import java.security.Security;

import com.distrimind.bouncycastle.tls.HashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.util.Strings;

class JcaUtils
{
    static String getJcaAlgorithmName(SignatureAndHashAlgorithm algorithm)
    {
        return (HashAlgorithm.getName(algorithm.getHash()) + "WITH"
            + Strings.toUpperCase(SignatureAlgorithm.getName(algorithm.getSignature())));
    }

    static boolean isSunMSCAPIProviderActive()
    {
        return null != Security.getProvider("SunMSCAPI");
    }

    static boolean isSunMSCAPIProvider(Provider provider)
    {
        return null != provider && isSunMSCAPIProviderName(provider.getName());
    }

    static boolean isSunMSCAPIProviderName(String providerName)
    {
        return "SunMSCAPI".equals(providerName);
    }
}
