package com.distrimind.bouncycastle.pkcs;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.MacCalculator;
import com.distrimind.bouncycastle.operator.OperatorCreationException;

public interface PKCS12MacCalculatorBuilder
{
    MacCalculator build(char[] password)
        throws OperatorCreationException;

    AlgorithmIdentifier getDigestAlgorithmIdentifier();
}
