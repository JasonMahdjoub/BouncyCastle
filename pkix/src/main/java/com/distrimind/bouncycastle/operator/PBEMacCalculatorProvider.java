package com.distrimind.bouncycastle.operator;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface PBEMacCalculatorProvider
{
    MacCalculator get(AlgorithmIdentifier algorithm, char[] password)
        throws OperatorCreationException;
}
