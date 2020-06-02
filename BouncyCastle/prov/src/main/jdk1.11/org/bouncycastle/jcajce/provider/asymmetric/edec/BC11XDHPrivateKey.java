package org.bouncycastle.bcjcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

import org.bouncycastle.bcasn1.ASN1Encodable;
import org.bouncycastle.bcasn1.ASN1OctetString;
import org.bouncycastle.bcasn1.ASN1Set;
import org.bouncycastle.bcasn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.bcasn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.bccrypto.params.AsymmetricKeyParameter;
import org.bouncycastle.bccrypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.bccrypto.params.X448PrivateKeyParameters;
import org.bouncycastle.bccrypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.bcjcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.bcjcajce.interfaces.XDHPublicKey;
import org.bouncycastle.bcutil.Arrays;

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
