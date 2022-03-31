package com.distrimind.bouncycastle.bcpg.sig;

import com.distrimind.bouncycastle.bcpg.SignatureSubpacket;
import com.distrimind.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Packet embedded signature
 */
public class EmbeddedSignature
    extends SignatureSubpacket
{
    public EmbeddedSignature(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.EMBEDDED_SIGNATURE, critical, isLongLength, data);
    }
}