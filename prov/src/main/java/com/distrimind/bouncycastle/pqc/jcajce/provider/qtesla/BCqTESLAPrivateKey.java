package com.distrimind.bouncycastle.pqc.jcajce.provider.qtesla;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import com.distrimind.bouncycastle.asn1.ASN1Set;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import com.distrimind.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import com.distrimind.bouncycastle.pqc.jcajce.interfaces.QTESLAKey;
import com.distrimind.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
import com.distrimind.bouncycastle.pqc.legacy.crypto.qtesla.QTESLAPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.qtesla.QTESLASecurityCategory;
import com.distrimind.bouncycastle.util.Arrays;

public class BCqTESLAPrivateKey
    implements PrivateKey, QTESLAKey
{
    private static final long serialVersionUID = 1L;

    private transient QTESLAPrivateKeyParameters keyParams;
    private transient ASN1Set attributes;

    public BCqTESLAPrivateKey(
        QTESLAPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    public BCqTESLAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.keyParams = (QTESLAPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * @return name of the algorithm
     */
    public final String getAlgorithm()
    {
        return QTESLASecurityCategory.getName(keyParams.getSecurityCategory());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public QTESLAParameterSpec getParams()
    {
        return new QTESLAParameterSpec(getAlgorithm());
    }

    public byte[] getEncoded()
    {
        PrivateKeyInfo pki;
        try
        {
            pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParams, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCqTESLAPrivateKey)
        {
            BCqTESLAPrivateKey otherKey = (BCqTESLAPrivateKey)o;

            return keyParams.getSecurityCategory() == otherKey.keyParams.getSecurityCategory()
                && Arrays.areEqual(keyParams.getSecret(), otherKey.keyParams.getSecret());
        }

        return false;
    }

    public int hashCode()
    {
        return keyParams.getSecurityCategory() + 37 * Arrays.hashCode(keyParams.getSecret());
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
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
