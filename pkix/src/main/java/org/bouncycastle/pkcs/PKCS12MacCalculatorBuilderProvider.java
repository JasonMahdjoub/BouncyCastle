package org.bouncycastle.pkcs;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface PKCS12MacCalculatorBuilderProvider
{
    PKCS12MacCalculatorBuilder get(AlgorithmIdentifier algorithmIdentifier);
}
