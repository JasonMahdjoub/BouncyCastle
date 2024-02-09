package com.distrimind.bouncycastle.pqc.jcajce.interfaces;

import com.distrimind.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;

import java.security.Key;

public interface SABERKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SABERParameterSpec
     */
    SABERParameterSpec getParameterSpec();
}
