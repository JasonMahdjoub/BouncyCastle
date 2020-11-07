package com.distrimind.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.ASN1Set;
import com.distrimind.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.X448PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import com.distrimind.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import com.distrimind.bouncycastle.jcajce.interfaces.XDHPublicKey;
import com.distrimind.bouncycastle.util.Arrays;

class BC11XDHPrivateKey
    extends BCXDHPrivateKey
    implements XECPrivateKey
{
    BC11XDHPrivateKey(AsymmetricKeyParameter privKey)
    {
        super(privKey);
    }

    BC11XDHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        super(keyInfo);
    }

    public AlgorithmParameterSpec getParams()
    {
        if (xdhPrivateKey instanceof X448PrivateKeyParameters)
        {
            return NamedParameterSpec.X448;
        }
        else
        {
            return NamedParameterSpec.X25519;
        }
    }

    public Optional<byte[]> getScalar()
    {
        if (xdhPrivateKey instanceof X448PrivateKeyParameters)
        {
            return Optional.of(((X448PrivateKeyParameters)xdhPrivateKey).getEncoded());
        }
        else
        {
            return Optional.of(((X25519PrivateKeyParameters)xdhPrivateKey).getEncoded());
        }
    }
}
