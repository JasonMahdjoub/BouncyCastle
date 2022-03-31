package com.distrimind.bouncycastle.jce.interfaces;

import javax.crypto.interfaces.DHKey;

import com.distrimind.bouncycastle.jce.spec.ElGamalParameterSpec;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}
