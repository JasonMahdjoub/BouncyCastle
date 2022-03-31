package com.distrimind.bouncycastle.jce.spec;

/**
 * A simple object to indicate that a symmetric cipher should reuse the
 * last key provided.
 * @deprecated use super class com.distrimind.bouncycastle.jcajce.spec.RepeatedSecretKeySpec
 */
public class RepeatedSecretKeySpec
    extends com.distrimind.bouncycastle.jcajce.spec.RepeatedSecretKeySpec
{
    private String algorithm;

    public RepeatedSecretKeySpec(String algorithm)
    {
        super(algorithm);
    }
}
