package com.distrimind.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.macs.HMac;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.BigIntegers;

/**
 * A deterministic K calculator based on the algorithm in section 3.2 of RFC 6979.
 */
public class HMacDSAKCalculator
    implements DSAKCalculator
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private final HMac hMac;
    private final byte[] K;
    private final byte[] V;

    private BigInteger n;

    /**
     * Base constructor.
     *
     * @param digest digest to build the HMAC on.
     */
    public HMacDSAKCalculator(Digest digest)
    {
        this.hMac = new HMac(digest);
        this.V = new byte[hMac.getMacSize()];
        this.K = new byte[hMac.getMacSize()];
    }

    public boolean isDeterministic()
    {
        return true;
    }

    public void init(BigInteger n, SecureRandom random)
    {
        throw new IllegalStateException("Operation not supported");
    }

    public void init(BigInteger n, BigInteger d, byte[] message)
    {
        this.n = n;

        Arrays.fill(V, (byte)0x01);
        Arrays.fill(K, (byte)0);

        int size = BigIntegers.getUnsignedByteLength(n);
        byte[] x = new byte[size];
        byte[] dVal = BigIntegers.asUnsignedByteArray(d);

        System.arraycopy(dVal, 0, x, x.length - dVal.length, dVal.length);

        byte[] m = new byte[size];

        BigInteger mInt = bitsToInt(message);

        if (mInt.compareTo(n) >= 0)
        {
            mInt = mInt.subtract(n);
        }

        byte[] mVal = BigIntegers.asUnsignedByteArray(mInt);

        System.arraycopy(mVal, 0, m, m.length - mVal.length, mVal.length);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);
        hMac.update((byte)0x00);
        hMac.update(x, 0, x.length);
        hMac.update(m, 0, m.length);
        initAdditionalInput0(hMac);

        hMac.doFinal(K, 0);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);

        hMac.doFinal(V, 0);

        hMac.update(V, 0, V.length);
        hMac.update((byte)0x01);
        hMac.update(x, 0, x.length);
        hMac.update(m, 0, m.length);

        hMac.doFinal(K, 0);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);

        hMac.doFinal(V, 0);
    }

    public BigInteger nextK()
    {
        byte[] t = new byte[BigIntegers.getUnsignedByteLength(n)];

        for (;;)
        {
            int tOff = 0;

            while (tOff < t.length)
            {
                hMac.update(V, 0, V.length);

                hMac.doFinal(V, 0);

                int len = Math.min(t.length - tOff, V.length);
                System.arraycopy(V, 0, t, tOff, len);
                tOff += len;
            }

            BigInteger k = bitsToInt(t);

            if (k.compareTo(ZERO) > 0 && k.compareTo(n) < 0)
            {
                return k;
            }

            hMac.update(V, 0, V.length);
            hMac.update((byte)0x00);

            hMac.doFinal(K, 0);

            hMac.init(new KeyParameter(K));

            hMac.update(V, 0, V.length);

            hMac.doFinal(V, 0);
        }
    }

    /**
     * RFC 6979 3.6. Additional data may be added to the input of HMAC [..]. A use case may be a protocol that
     * requires a non-deterministic signature algorithm on a system that does not have access to a
     * high-quality random source. It suffices that the additional data [..] is non-repeating (e.g., a
     * signature counter or a monotonic clock) to ensure "random-looking" signatures are indistinguishable, in
     * a cryptographic way, from plain (EC)DSA signatures.
     * <p/>
     * By default there is no additional input. Override this method to supply additional input, bearing in
     * mind that this calculator may be used for many signatures.
     *
     * @param hmac0 the {@link HMac} to which the additional input should be added.
     */
    protected void initAdditionalInput0(HMac hmac0)
    {
    }

    private BigInteger bitsToInt(byte[] t)
    {
        BigInteger v = new BigInteger(1, t);

        if (t.length * 8 > n.bitLength())
        {
            v = v.shiftRight(t.length * 8 - n.bitLength());
        }

        return v;
    }
}
