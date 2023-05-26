package com.distrimind.bouncycastle.bcpg;

import java.io.IOException;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.io.Streams;

public class PaddingPacket
    extends ContainedPacket
{
    private final byte[] padding;

    public PaddingPacket(BCPGInputStream in)
        throws IOException
    {
        padding = Streams.readAll(in);
    }

    public PaddingPacket(byte[] padding)
    {
        this.padding = padding;
    }

    public PaddingPacket(int octetLen, SecureRandom random)
    {
        this(randomBytes(octetLen, random));
    }

    private static byte[] randomBytes(int octetCount, SecureRandom random)
    {
        byte[] bytes = new byte[octetCount];
        random.nextBytes(bytes);
        return bytes;
    }

    public byte[] getPadding()
    {
        return Arrays.clone(padding);
    }

    @Override
    public void encode(BCPGOutputStream pOut)
        throws IOException
    {
        pOut.writePacket(PADDING, padding);
    }
}
