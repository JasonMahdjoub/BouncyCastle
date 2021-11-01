package com.distrimind.bouncycastle.jcajce.provider.symmetric.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.spec.AlgorithmParameterSpec;

import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.internal.asn1.cms.GCMParameters;
import com.distrimind.bouncycastle.crypto.params.AEADParameters;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.util.Integers;

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
