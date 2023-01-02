package com.distrimind.bouncycastle.pqc.jcajce.provider.kyber;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import com.distrimind.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.distrimind.bouncycastle.pqc.jcajce.interfaces.KyberPublicKey;
import com.distrimind.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import com.distrimind.bouncycastle.util.Arrays;

public class BCKyberPublicKey
    implements KyberPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient KyberPublicKeyParameters params;

    public BCKyberPublicKey(
        KyberPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCKyberPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (KyberPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this Kyber public key with another object.
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

        if (o instanceof BCKyberPublicKey)
        {
            BCKyberPublicKey otherKey = (BCKyberPublicKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "Kyber"
     */
    public final String getAlgorithm()
    {
        return "Kyber";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    public KyberParameterSpec getParameterSpec()
    {
        return KyberParameterSpec.fromName(params.getParameters().getName());
    }

    KyberPublicKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
