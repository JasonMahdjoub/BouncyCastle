package org.bouncycastle.operator;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface InputDecryptorProvider
{
    public InputDecryptor get(AlgorithmIdentifier algorithm)
        throws OperatorCreationException;
}
