package com.distrimind.bouncycastle.crypto.test;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.crypto.DerivationFunction;
import com.distrimind.bouncycastle.crypto.DerivationParameters;
import com.distrimind.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
import com.distrimind.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import com.distrimind.bouncycastle.crypto.digests.SHA1Digest;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;

/**
 * DHKEK Generator tests - from RFC 2631.
 */
public class DHKEKGeneratorTest
    extends SimpleTest
{
    private byte[] seed1 = Hex.decode("000102030405060708090a0b0c0d0e0f10111213");
    private ASN1ObjectIdentifier alg1 = PKCSObjectIdentifiers.id_alg_CMS3DESwrap;
    private byte[] result1 = Hex.decode("a09661392376f7044d9052a397883246b67f5f1ef63eb5fb");

    private byte[] seed2 = Hex.decode("000102030405060708090a0b0c0d0e0f10111213");
    private ASN1ObjectIdentifier alg2 = PKCSObjectIdentifiers.id_alg_CMSRC2wrap;
    private byte[] partyAInfo = Hex.decode(
                                     "0123456789abcdeffedcba9876543201"
                                   + "0123456789abcdeffedcba9876543201"
                                   + "0123456789abcdeffedcba9876543201"
                                   + "0123456789abcdeffedcba9876543201");
    private byte[] result2 = Hex.decode("48950c46e0530075403cce72889604e0");

    public DHKEKGeneratorTest()
    {
    }

    public void performTest()
    {
        checkMask(1, new DHKEKGenerator(new SHA1Digest()), new DHKDFParameters(alg1, 192, seed1), result1);
        checkMask(2, new DHKEKGenerator(new SHA1Digest()), new DHKDFParameters(alg2, 128, seed2, partyAInfo), result2);
    }

    private void checkMask(
        int                count,
        DerivationFunction kdf,
        DerivationParameters params,
        byte[]             result)
    {
        byte[]             data = new byte[result.length];

        kdf.init(params);

        kdf.generateBytes(data, 0, data.length);

        if (!areEqual(result, data))
        {
            fail("DHKEKGenerator failed generator test " + count);
        }
    }

    public String getName()
    {
        return "DHKEKGenerator";
    }

    public static void main(
        String[]    args)
    {
        runTest(new DHKEKGeneratorTest());
    }
}
