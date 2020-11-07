package com.distrimind.bouncycastle.jce.provider;

import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jce.spec.ECParameterSpec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ProviderUtil
{
    private static final long  MAX_MEMORY = Integer.MAX_VALUE;

    private static volatile ECParameterSpec ecImplicitCaParams;

    static void setParameter(String parameterName, Object parameter)
    {
        if (parameterName.equals(ConfigurableProvider.EC_IMPLICITLY_CA))
        {
            if (parameter instanceof ECParameterSpec || parameter == null)
            {
                ecImplicitCaParams = (ECParameterSpec)parameter;
            }
        }
    }

    public static ECParameterSpec getEcImplicitlyCa()
    {
        return ecImplicitCaParams;
    }

    static int getReadLimit(InputStream in)
        throws IOException
    {
        if (in instanceof ByteArrayInputStream)
        {
            return in.available();
        }

        if (MAX_MEMORY > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }

        return (int)MAX_MEMORY;
    }
}
