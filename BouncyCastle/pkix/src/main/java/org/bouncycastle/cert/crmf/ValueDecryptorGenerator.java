package org.bouncycastle.cert.crmf;

import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.InputDecryptor;

public interface ValueDecryptorGenerator
{
    InputDecryptor getValueDecryptor(AlgorithmIdentifier keyAlg, AlgorithmIdentifier symmAlg, byte[] encKey)
        throws CRMFException;
}
