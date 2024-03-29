package com.distrimind.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.crypto.digests.SHA256Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA512Digest;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSMT;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature;
import com.distrimind.bouncycastle.util.Arrays;

/**
 * Test cases for XMSSReducedSignature class.
 */
public class XMSSReducedSignatureTest
    extends TestCase
{

    public void testSignatureParsingSHA256()
    {
        XMSSMTParameters params = new XMSSMTParameters(8, 2, new SHA256Digest());
        XMSSMT mt = new XMSSMT(params, new NullPRNG());
        mt.generateKeys();
        byte[] message = new byte[1024];
        byte[] sig1 = mt.sign(message);
        XMSSMTSignature sig2 = new XMSSMTSignature.Builder(params).withSignature(sig1).build();

        XMSSReducedSignature reducedSignature1 = sig2.getReducedSignatures().get(0);
        byte[] reducedSignatureBinary = reducedSignature1.toByteArray();
        XMSSReducedSignature reducedSignature2 = new XMSSReducedSignature.Builder(new XMSSParameters(4, new SHA256Digest())).withReducedSignature(reducedSignatureBinary).build();

        assertTrue(Arrays.areEqual(reducedSignatureBinary, reducedSignature2.toByteArray()));
    }

    public void testSignatureParsingSHA512()
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA512Digest());
        XMSSMT mt = new XMSSMT(params, new NullPRNG());
        mt.generateKeys();
        byte[] message = new byte[1024];
        byte[] sig1 = mt.sign(message);
        XMSSMTSignature sig2 = new XMSSMTSignature.Builder(params).withSignature(sig1).build();

        XMSSReducedSignature reducedSignature1 = sig2.getReducedSignatures().get(0);
        byte[] reducedSignatureBinary = reducedSignature1.toByteArray();
        XMSSReducedSignature reducedSignature2 = new XMSSReducedSignature.Builder(new XMSSParameters(2, new SHA512Digest())).withReducedSignature(reducedSignatureBinary).build();

        assertTrue(Arrays.areEqual(reducedSignatureBinary, reducedSignature2.toByteArray()));
    }

    public void testConstructor()
    {
        XMSSReducedSignature sig = new XMSSReducedSignature.Builder(new XMSSParameters(4, new SHA512Digest())).build();

        byte[] sigByte = sig.toByteArray();
        /* check everything is 0 */
        for (int i = 0; i < sigByte.length; i++)
        {
            assertEquals(0x00, sigByte[i]);
        }
    }
}
