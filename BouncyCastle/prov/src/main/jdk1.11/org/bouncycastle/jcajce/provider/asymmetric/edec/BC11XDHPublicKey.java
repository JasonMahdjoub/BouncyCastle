package org.bouncycastle.bcjcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

import org.bouncycastle.bcasn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.bcasn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.bccrypto.params.AsymmetricKeyParameter;
import org.bouncycastle.bccrypto.params.X25519PublicKeyParameters;
import org.bouncycastle.bccrypto.params.X448PublicKeyParameters;
import org.bouncycastle.bcjcajce.interfaces.XDHPublicKey;
import org.bouncycastle.bcutil.Arrays;

class BC11XDHPublicKey
    extends BCXDHPublicKey
    implements XECPublicKey
{
    BC11XDHPublicKey(AsymmetricKeyParameter pubKey)
    {
        super(pubKey);
    }

    BC11XDHPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        super(keyInfo);
    }

    BC11XDHPublicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        super(prefix, rawData);
    }

    public AlgorithmParameterSpec getParams()
    {
        if (xdhPublicKey instanceof X448PublicKeyParameters)
        {
            return NamedParameterSpec.X448;
        }
        else
        {
            return NamedParameterSpec.X25519;
        }
    }

    public BigInteger getU()
    {
        if (xdhPublicKey instanceof X448PublicKeyParameters)
        {
            return new BigInteger(1, ((X448PublicKeyParameters)xdhPublicKey).getEncoded());
        }
        else
        {
            return new BigInteger(1, ((X25519PublicKeyParameters)xdhPublicKey).getEncoded());
        }
    }
}
