package org.bouncycastle.cms.jcajce;

import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;

interface KeyMaterialGenerator
{
    byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}
