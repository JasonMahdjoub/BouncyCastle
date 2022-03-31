package com.distrimind.bouncycastle.jsse;

import com.distrimind.bouncycastle.tls.NameType;
import com.distrimind.bouncycastle.tls.TlsUtils;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Hex;

public abstract class BCSNIServerName
{
    private final int nameType;
    private final byte[] encoded;

    protected BCSNIServerName(int nameType, byte[] encoded)
    {
        if (!TlsUtils.isValidUint8(nameType))
        {
            throw new IllegalArgumentException("'nameType' should be between 0 and 255");
        }
        if (encoded == null)
        {
            throw new NullPointerException("'encoded' cannot be null");
        }

        this.nameType = nameType;
        this.encoded = TlsUtils.clone(encoded);
    }

    public final int getType()
    {
        return nameType;
    }

    public final byte[] getEncoded()
    {
        return (byte[])TlsUtils.clone(encoded);
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof BCSNIServerName))
        {
            return false;
        }
        BCSNIServerName other = (BCSNIServerName)obj;
        return nameType == other.nameType
            && Arrays.areEqual(encoded, other.encoded);
    }

    @Override
    public int hashCode()
    {
        return nameType ^ Arrays.hashCode(encoded);
    }

    @Override
    public String toString()
    {
        return "{type=" + NameType.getText((short)nameType) + ", value=" + Hex.toHexString(encoded) + "}";
    }
}
