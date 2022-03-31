package com.distrimind.bouncycastle.cert.crmf;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.InputDecryptor;

public interface ValueDecryptorGenerator
{
    InputDecryptor getValueDecryptor(AlgorithmIdentifier keyAlg, AlgorithmIdentifier symmAlg, byte[] encKey)
        throws CRMFException;
}
