package com.distrimind.bouncycastle.bcpg.sig;

import com.distrimind.bouncycastle.bcpg.SignatureSubpacket;
import com.distrimind.bouncycastle.bcpg.SignatureSubpacketTags;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.Strings;

/**
 * packet giving the User ID of the signer.
 */
public class SignerUserID 
    extends SignatureSubpacket
{
    public SignerUserID(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, isLongLength, data);
    }
    
    public SignerUserID(
        boolean    critical,
        String     userID)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, false, Strings.toUTF8ByteArray(userID));
    }
    
    public String getID()
    {
        return Strings.fromUTF8ByteArray(data);
    }

    public byte[] getRawID()
    {
        return Arrays.clone(data);
    }
}
