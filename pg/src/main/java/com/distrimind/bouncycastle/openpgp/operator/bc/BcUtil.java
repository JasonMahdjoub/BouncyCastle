package com.distrimind.bouncycastle.openpgp.operator.bc;

import java.io.InputStream;
import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.x9.ECNamedCurveTable;
import com.distrimind.bouncycastle.asn1.x9.X9ECParameters;
import com.distrimind.bouncycastle.bcpg.AEADEncDataPacket;
import com.distrimind.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import com.distrimind.bouncycastle.openpgp.PGPSessionKey;
import com.distrimind.bouncycastle.openpgp.operator.PGPDataDecryptor;
import com.distrimind.bouncycastle.openpgp.operator.PGPDigestCalculator;
import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.BufferedBlockCipher;
import com.distrimind.bouncycastle.crypto.DefaultBufferedBlockCipher;
import com.distrimind.bouncycastle.crypto.ec.CustomNamedCurves;
import com.distrimind.bouncycastle.crypto.io.CipherInputStream;
import com.distrimind.bouncycastle.crypto.modes.CFBBlockCipher;
import com.distrimind.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.crypto.params.ParametersWithIV;
import com.distrimind.bouncycastle.math.ec.ECCurve;
import com.distrimind.bouncycastle.math.ec.ECPoint;
import com.distrimind.bouncycastle.util.BigIntegers;

public class BcUtil
{
    static BufferedBlockCipher createStreamCipher(boolean forEncryption, BlockCipher engine, boolean withIntegrityPacket, byte[] key)
    {
        BufferedBlockCipher c;

        if (withIntegrityPacket)
        {
            c = new DefaultBufferedBlockCipher(CFBBlockCipher.newInstance(engine, engine.getBlockSize() * 8));
        }
        else
        {
            c = new DefaultBufferedBlockCipher(new OpenPGPCFBBlockCipher(engine));
        }

        KeyParameter keyParameter = new KeyParameter(key);

        if (withIntegrityPacket)
        {
            c.init(forEncryption, new ParametersWithIV(keyParameter, new byte[engine.getBlockSize()]));
        }
        else
        {
            c.init(forEncryption, keyParameter);
        }

        return c;
    }

    /**
     * Create a new OpenPGP v4 data decryptor.
     * This decryptor can handle Symmetrically Encrypted Data (SED) and v1 Symmetrically Encrypted Integrity-Protected
     * Data (SEIPD) packets.
     * For AEAD packets, see {@link BcAEADUtil#createOpenPgpV5DataDecryptor(AEADEncDataPacket, PGPSessionKey)} and
     * {@link BcAEADUtil#createOpenPgpV6DataDecryptor(SymmetricEncIntegrityPacket, PGPSessionKey)}.
     * @param withIntegrityPacket if true, the data is contained in a SEIPD v1 packet, if false it is contained in a
     *                            SED packet.
     * @param engine decryption engine
     * @param key decryption key
     * @return decryptor
     */
    public static PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, BlockCipher engine, byte[] key)
    {
        final BufferedBlockCipher c = createStreamCipher(false, engine, withIntegrityPacket, key);

        return new PGPDataDecryptor()
        {
            public InputStream getInputStream(InputStream in)
            {
                return new CipherInputStream(in, c);
            }

            public int getBlockSize()
            {
                return c.getBlockSize();
            }

            public PGPDigestCalculator getIntegrityCalculator()
            {
                return new SHA1PGPDigestCalculator();
            }
        };
    }

    public static BufferedBlockCipher createSymmetricKeyWrapper(boolean forEncryption, BlockCipher engine, byte[] key, byte[] iv)
    {
        BufferedBlockCipher c = new DefaultBufferedBlockCipher(CFBBlockCipher.newInstance(engine, engine.getBlockSize() * 8));

        c.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));

        return c;
    }

    static X9ECParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
    {
        X9ECParameters x9 = CustomNamedCurves.getByOID(curveOID);
        if (x9 == null)
        {
            x9 = ECNamedCurveTable.getByOID(curveOID);
        }

        return x9;
    }

    static ECPoint decodePoint(
        BigInteger encodedPoint,
        ECCurve curve)
    {
        return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
    }
}
