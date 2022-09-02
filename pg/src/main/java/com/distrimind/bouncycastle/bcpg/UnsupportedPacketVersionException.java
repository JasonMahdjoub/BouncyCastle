package com.distrimind.bouncycastle.bcpg;

public class UnsupportedPacketVersionException
    extends RuntimeException
{
    public UnsupportedPacketVersionException(String msg)
    {
        super(msg);
    }
}
