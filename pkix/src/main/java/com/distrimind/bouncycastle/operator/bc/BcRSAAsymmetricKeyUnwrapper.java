package com.distrimind.bouncycastle.operator.bc;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.AsymmetricBlockCipher;
import com.distrimind.bouncycastle.crypto.encodings.PKCS1Encoding;
import com.distrimind.bouncycastle.crypto.engines.RSABlindedEngine;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class BcRSAAsymmetricKeyUnwrapper
    extends BcAsymmetricKeyUnwrapper
{
    public BcRSAAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey)
    {
        super(encAlgId, privateKey);
    }

    protected AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm)
    {
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
