package com.distrimind.bouncycastle.openpgp.operator;

import com.distrimind.bouncycastle.bcpg.PublicKeyPacket;
import com.distrimind.bouncycastle.openpgp.PGPException;

public interface KeyFingerPrintCalculator
{
    byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException;
}
