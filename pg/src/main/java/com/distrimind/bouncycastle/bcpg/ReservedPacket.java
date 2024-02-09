package com.distrimind.bouncycastle.bcpg;

public class ReservedPacket
    extends InputStreamPacket
{
    public ReservedPacket(BCPGInputStream in)
    {
        super(in, RESERVED);
    }
}
