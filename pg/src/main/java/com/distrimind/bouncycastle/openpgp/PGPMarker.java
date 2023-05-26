/*
 * Created on Mar 6, 2004
 *
 * To change this generated comment go to 
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package com.distrimind.bouncycastle.openpgp;

import java.io.IOException;

import com.distrimind.bouncycastle.bcpg.MarkerPacket;
import com.distrimind.bouncycastle.bcpg.Packet;
import com.distrimind.bouncycastle.bcpg.BCPGInputStream;

/**
 * a PGP marker packet - in general these should be ignored other than where
 * the idea is to preserve the original input stream.
 */
public class PGPMarker
{
    private MarkerPacket p;
    
    /**
     * Default constructor.
     * 
     * @param in
     * @throws IOException
     */
    public PGPMarker(
        BCPGInputStream in) 
        throws IOException
    {
        Packet packet = in.readPacket();
        if (!(packet instanceof MarkerPacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }
        p = (MarkerPacket)packet;
    }
}
