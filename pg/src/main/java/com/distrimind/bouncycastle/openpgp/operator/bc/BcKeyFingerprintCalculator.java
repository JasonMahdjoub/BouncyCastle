package com.distrimind.bouncycastle.openpgp.operator.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.bcpg.BCPGKey;
import com.distrimind.bouncycastle.bcpg.MPInteger;
import com.distrimind.bouncycastle.bcpg.PublicKeyPacket;
import com.distrimind.bouncycastle.bcpg.RSAPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.UnsupportedPacketVersionException;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.digests.MD5Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA1Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA256Digest;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

public class BcKeyFingerprintCalculator
    implements KeyFingerPrintCalculator
{
    public byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException
    {
        BCPGKey key = publicPk.getKey();
        Digest digest;

        if (publicPk.getVersion() <= 3)
        {
            RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

            try
            {
                digest = new MD5Digest();

                byte[] bytes = new MPInteger(rK.getModulus()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);

                bytes = new MPInteger(rK.getPublicExponent()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else if (publicPk.getVersion() == 4)
        {
            try
            {
                byte[] kBytes = publicPk.getEncodedContents();

                digest = new SHA1Digest();

                digest.update((byte)0x99);
                digest.update((byte)(kBytes.length >> 8));
                digest.update((byte)kBytes.length);
                digest.update(kBytes, 0, kBytes.length);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else if (publicPk.getVersion() == 6)
        {
            try
            {
                byte[] kBytes = publicPk.getEncodedContents();
                digest = new SHA256Digest();

                digest.update((byte)0x9b);

                digest.update((byte)(kBytes.length >> 24));
                digest.update((byte)(kBytes.length >> 16));
                digest.update((byte)(kBytes.length >> 8));
                digest.update((byte)kBytes.length);

                digest.update(kBytes, 0, kBytes.length);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported PGP key version: " + publicPk.getVersion());
        }

        byte[] digBuf = new byte[digest.getDigestSize()];

        digest.doFinal(digBuf, 0);

        return digBuf;
    }
}
