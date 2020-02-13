package org.bouncycastle.operator;

import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;

public interface MacCalculatorProvider
{
    public MacCalculator get(AlgorithmIdentifier algorithm);
}
