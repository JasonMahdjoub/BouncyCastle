package org.bouncycastle.operator.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.crypto.AsymmetricBlockCipher;
import com.distrimind.bouncycastle.crypto.encodings.PKCS1Encoding;
import com.distrimind.bouncycastle.crypto.engines.RSABlindedEngine;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.util.PublicKeyFactory;

public class BcRSAAsymmetricKeyWrapper
    extends BcAsymmetricKeyWrapper
{
    public BcRSAAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey)
    {
        super(encAlgId, publicKey);
    }

    public BcRSAAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        super(encAlgId, PublicKeyFactory.createKey(publicKeyInfo));
    }

    protected AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm)
    {
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
