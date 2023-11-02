package com.distrimind.bouncycastle.bcpg;

import java.io.IOException;

import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.Strings;

/**
 * Basic type for a user ID packet.
 */
public class UserIDPacket 
    extends ContainedPacket
    implements UserDataPacket
{    
    private byte[]    idData;
    
    public UserIDPacket(
        BCPGInputStream  in)
        throws IOException
    {
        super(USER_ID);

        this.idData = in.readAll();
    }

    public UserIDPacket(
        String    id)
    {
        super(USER_ID);

        this.idData = Strings.toUTF8ByteArray(id);
    }

    public UserIDPacket(byte[] rawID)
    {
        super(USER_ID);

        this.idData = Arrays.clone(rawID);
    }

    public String getID()
    {
        return Strings.fromUTF8ByteArray(idData);
    }

    public byte[] getRawID()
    {
        return Arrays.clone(idData);
    }

    public boolean equals(Object o)
    {
        if (o instanceof UserIDPacket)
        {
            return Arrays.areEqual(this.idData, ((UserIDPacket)o).idData);
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(this.idData);
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(USER_ID, idData);
    }
}
