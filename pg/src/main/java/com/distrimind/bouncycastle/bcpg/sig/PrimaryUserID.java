package com.distrimind.bouncycastle.bcpg.sig;

import com.distrimind.bouncycastle.bcpg.SignatureSubpacket;
import com.distrimind.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving whether or not the signature is signed using the primary user ID for the key.
 */
public class PrimaryUserID 
    extends SignatureSubpacket
{    
    private static byte[] booleanToByteArray(
        boolean    value)
    {
        byte[]    data = new byte[1];
            
        if (value)
        {
            data[0] = 1;
            return data;
        }
        else
        {
            return data;
        }
    }
    
    public PrimaryUserID(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.PRIMARY_USER_ID, critical, isLongLength, data);
    }
    
    public PrimaryUserID(
        boolean    critical,
        boolean    isPrimaryUserID)
    {
        super(SignatureSubpacketTags.PRIMARY_USER_ID, critical, false, booleanToByteArray(isPrimaryUserID));
    }
    
    public boolean isPrimaryUserID()
    {
        return data[0] != 0;
    }
}
