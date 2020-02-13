package org.bouncycastle.pkcs;

import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;

public interface PKCS12MacCalculatorBuilderProvider
{
    PKCS12MacCalculatorBuilder get(AlgorithmIdentifier algorithmIdentifier);
}
