package com.distrimind.bouncycastle.operator;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface MacCalculatorProvider
{
    public MacCalculator get(AlgorithmIdentifier algorithm);
}
