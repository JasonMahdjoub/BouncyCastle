package com.distrimind.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import com.distrimind.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public interface DilithiumKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a DilithiumParameterSpec
     */
    DilithiumParameterSpec getParameterSpec();
}
