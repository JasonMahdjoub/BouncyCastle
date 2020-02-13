package org.bouncycastle.operator;

import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;

public interface InputDecryptorProvider
{
    public InputDecryptor get(AlgorithmIdentifier algorithm)
        throws OperatorCreationException;
}
