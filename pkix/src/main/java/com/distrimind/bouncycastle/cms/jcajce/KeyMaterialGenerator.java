package com.distrimind.bouncycastle.cms.jcajce;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;

interface KeyMaterialGenerator
{
    byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}
