package org.bouncycastle.bcjcajce.provider.symmetric.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.bcasn1.ASN1Primitive;
import org.bouncycastle.bcasn1.cms.GCMParameters;
import org.bouncycastle.bccrypto.params.AEADParameters;
import org.bouncycastle.bccrypto.params.KeyParameter;
import org.bouncycastle.bcutil.Integers;

public class GcmSpecUtil
{
    private static Method extractMethod(final String name)
    {
	return null;
    }

    public static boolean gcmSpecExists()
    {
        return false;
    }

    public static boolean isGcmSpec(AlgorithmParameterSpec paramSpec)
    {
        return false;
    }

    public static boolean isGcmSpec(Class paramSpecClass)
    {
        return false;
    }

    public static AlgorithmParameterSpec extractGcmSpec(ASN1Primitive spec)
    {
	return null;
    }

    static AEADParameters extractAeadParameters(final KeyParameter keyParam, final AlgorithmParameterSpec params)
    {
	return null;
    }

    public static GCMParameters extractGcmParameters(final AlgorithmParameterSpec paramSpec)
    {
	return null;
    }
}
