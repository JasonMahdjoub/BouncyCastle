package com.distrimind.bouncycastle.pqc.jcajce.provider.kyber;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.distrimind.bouncycastle.asn1.ASN1Set;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import com.distrimind.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import com.distrimind.bouncycastle.pqc.jcajce.interfaces.KyberPrivateKey;
import com.distrimind.bouncycastle.pqc.jcajce.interfaces.KyberPublicKey;
import com.distrimind.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.Strings;

public class BCKyberPrivateKey
    implements KyberPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient KyberPrivateKeyParameters params;
    private transient String algorithm;
    private transient ASN1Set attributes;

    public BCKyberPrivateKey(
            KyberPrivateKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    public BCKyberPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();;
        this.params = (KyberPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    /**
     * Compare this Kyber private key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCKyberPrivateKey)
        {
            BCKyberPrivateKey otherKey = (BCKyberPrivateKey)o;

            return Arrays.areEqual(getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "KYBER512, KYBER768, etc..."
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public KyberPublicKey getPublicKey()
    {
        return new BCKyberPublicKey(params.getPublicKeyParameters());
    }

    public KyberParameterSpec getParameterSpec()
    {
        return KyberParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    KyberPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
            ObjectInputStream in)
            throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
