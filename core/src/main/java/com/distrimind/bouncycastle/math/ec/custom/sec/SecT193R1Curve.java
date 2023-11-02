package com.distrimind.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import com.distrimind.bouncycastle.math.ec.AbstractECLookupTable;
import com.distrimind.bouncycastle.math.ec.ECConstants;
import com.distrimind.bouncycastle.math.ec.ECCurve;
import com.distrimind.bouncycastle.math.ec.ECCurve.AbstractF2m;
import com.distrimind.bouncycastle.math.ec.ECFieldElement;
import com.distrimind.bouncycastle.math.ec.ECLookupTable;
import com.distrimind.bouncycastle.math.ec.ECPoint;
import com.distrimind.bouncycastle.math.raw.Nat256;
import com.distrimind.bouncycastle.util.encoders.Hex;

public class SecT193R1Curve extends AbstractF2m
{
    private static final int SECT193R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;
    private static final ECFieldElement[] SECT193R1_AFFINE_ZS = new ECFieldElement[] { new SecT193FieldElement(ECConstants.ONE) }; 

    protected SecT193R1Point infinity;

    public SecT193R1Curve()
    {
        super(193, 15, 0, 0);

        this.infinity = new SecT193R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814")));
        this.order = new BigInteger(1, Hex.decodeStrict("01000000000000000000000000C7F34A778F443ACC920EBA49"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SECT193R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT193R1Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_LAMBDA_PROJECTIVE:
            return true;
        default:
            return false;
        }
    }

    public int getFieldSize()
    {
        return 193;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT193FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecT193R1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecT193R1Point(this, x, y, zs);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public boolean isKoblitz()
    {
        return false;
    }

    public int getM()
    {
        return 193;
    }

    public boolean isTrinomial()
    {
        return true;
    }

    public int getK1()
    {
        return 15;
    }

    public int getK2()
    {
        return 0;
    }

    public int getK3()
    {
        return 0;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_LONGS = 4;

        final long[] table = new long[len * FE_LONGS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat256.copy64(((SecT193FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_LONGS;
                Nat256.copy64(((SecT193FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_LONGS;
            }
        }

        return new AbstractECLookupTable()
        {
            public int getSize()
            {
                return len;
            }

            public ECPoint lookup(int index)
            {
                long[] x = Nat256.create64(), y = Nat256.create64();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    long MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_LONGS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_LONGS + j] & MASK;
                    }

                    pos += (FE_LONGS * 2);
                }

                return createPoint(x, y);
            }

            public ECPoint lookupVar(int index)
            {
                long[] x = Nat256.create64(), y = Nat256.create64();
                int pos = index * FE_LONGS * 2;

                for (int j = 0; j < FE_LONGS; ++j)
                {
                    x[j] = table[pos + j];
                    y[j] = table[pos + FE_LONGS + j];
                }

                return createPoint(x, y);
            }

            private ECPoint createPoint(long[] x, long[] y)
            {
                return createRawPoint(new SecT193FieldElement(x), new SecT193FieldElement(y), SECT193R1_AFFINE_ZS);
            }
        };
    }
}
