package com.distrimind.bouncycastle.bcpg;

import java.io.IOException;

/**
 * @deprecated Will be removed
 */
public abstract class OutputStreamPacket
{
    protected BCPGOutputStream    out;
    
    public OutputStreamPacket(
        BCPGOutputStream    out)
    {
        this.out = out;
    }
    
    public abstract BCPGOutputStream open() throws IOException;
    
    public abstract void close() throws IOException;
}
