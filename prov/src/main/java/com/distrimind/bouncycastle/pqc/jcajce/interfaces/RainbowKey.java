package com.distrimind.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import com.distrimind.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;

public interface RainbowKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a RainbowParameterSpec
     */
    RainbowParameterSpec getParameterSpec();
}
