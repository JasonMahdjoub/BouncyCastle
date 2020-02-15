package org.bouncycastle.jce.spec;

/**
 * A simple object to indicate that a symmetric cipher should reuse the
 * last key provided.
 * @deprecated use super class org.bouncycastle.bcjcajce.spec.RepeatedSecretKeySpec
 */
public class RepeatedSecretKeySpec
    extends org.bouncycastle.bcjcajce.spec.RepeatedSecretKeySpec
{
    private String algorithm;

    public RepeatedSecretKeySpec(String algorithm)
    {
        super(algorithm);
    }
}
