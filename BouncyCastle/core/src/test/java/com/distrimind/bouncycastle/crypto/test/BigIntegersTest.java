package com.distrimind.bouncycastle.crypto.test;

import java.math.BigInteger;

import com.distrimind.bouncycastle.util.BigIntegers;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.TestRandomData;

public class BigIntegersTest
    extends SimpleTest
{
    public String getName()
    {
        return "BigIntegers";
    }

    public void performTest()
        throws Exception
    {
        BigInteger min = BigInteger.valueOf(5);
        isTrue(min.equals(BigIntegers.createRandomPrime(min.bitLength(), 1,
            new TestRandomData(BigIntegers.asUnsignedByteArray(min)))));

        BigInteger max = BigInteger.valueOf(743);
        isTrue(max.equals(BigIntegers.createRandomPrime(max.bitLength(), 1,
            new TestRandomData(BigIntegers.asUnsignedByteArray(max)))));
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new BigIntegersTest());
    }
}
