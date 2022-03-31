package com.distrimind.bouncycastle.pqc.crypto.test;

import java.io.IOException;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA256Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA512Digest;
import com.distrimind.bouncycastle.crypto.digests.SHAKEDigest;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.distrimind.bouncycastle.util.Arrays;

/**
 * Test cases for XMSSPrivateKey class.
 */
public class XMSSPrivateKeyTest
    extends TestCase
{
    public void testPrivateKeyParsing()
        throws ClassNotFoundException, IOException
    {
        parsingTest(new SHA256Digest());
        parsingTest(new SHA512Digest());
        parsingTest(new SHAKEDigest(128));
        parsingTest(new SHAKEDigest(256));
    }

    private void parsingTest(Digest digest)
        throws ClassNotFoundException, IOException
    {
        XMSSParameters params = new XMSSParameters(10, digest);
        byte[] root = generateRoot(digest);
        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withRoot(root).build();

        byte[] export = privateKey.toByteArray();

        XMSSPrivateKeyParameters privateKey2 = new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(export).build();

        assertEquals(privateKey.getIndex(), privateKey2.getIndex());
        assertEquals(true, Arrays.areEqual(privateKey.getSecretKeySeed(), privateKey2.getSecretKeySeed()));
        assertEquals(true, Arrays.areEqual(privateKey.getSecretKeyPRF(), privateKey2.getSecretKeyPRF()));
        assertEquals(true, Arrays.areEqual(privateKey.getPublicSeed(), privateKey2.getPublicSeed()));
        assertEquals(true, Arrays.areEqual(privateKey.getRoot(), privateKey2.getRoot()));
    }

    private byte[] generateRoot(Digest digest)
    {
        byte[] rv = new byte[digest.getDigestSize()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = (byte)i;
        }

        return rv;
    }

}
