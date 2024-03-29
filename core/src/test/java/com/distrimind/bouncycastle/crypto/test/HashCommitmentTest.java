package com.distrimind.bouncycastle.crypto.test;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.Commitment;
import com.distrimind.bouncycastle.crypto.Committer;
import com.distrimind.bouncycastle.crypto.DataLengthException;
import com.distrimind.bouncycastle.crypto.commitments.GeneralHashCommitter;
import com.distrimind.bouncycastle.crypto.commitments.HashCommitter;
import com.distrimind.bouncycastle.crypto.digests.SHA1Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA256Digest;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class HashCommitmentTest
    extends SimpleTest
{
    public String getName()
    {
        return "HashCommitmentTest";
    }

    public void performBasicTest()
        throws Exception
    {
        byte[] data = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");

        Committer committer = new HashCommitter(SHA256Digest.newInstance(), new SecureRandom());

        Commitment c = committer.commit(data);

        committer = new HashCommitter(SHA256Digest.newInstance(), new SecureRandom());

        if (!committer.isRevealed(c, data))
        {
            fail("commitment failed to validate");
        }

        committer = new HashCommitter(new SHA1Digest(), new SecureRandom());

        if (committer.isRevealed(c, data))
        {
            fail("commitment validated!!");
        }

        try
        {
            committer.isRevealed(c, new byte[data.length + 1]);
        }
        catch (Exception e)
        {
            if (!e.getMessage().equals("Message and witness secret lengths do not match."))
            {
                fail("exception thrown but wrong message");
            }
        }

        // SHA1 has a block size of 512 bits, try a message that's too big

        try
        {
            c = committer.commit(new byte[33]);
        }
        catch (DataLengthException e)
        {
            if (!e.getMessage().equals("Message to be committed to too large for digest."))
            {
                fail("exception thrown but wrong message");
            }
        }
    }

    public void performGeneralTest()
        throws Exception
    {
        byte[] data = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");

        Committer committer = new GeneralHashCommitter(SHA256Digest.newInstance(), new SecureRandom());

        Commitment c = committer.commit(data);

        committer = new GeneralHashCommitter(SHA256Digest.newInstance(), new SecureRandom());

        if (!committer.isRevealed(c, data))
        {
            fail("general commitment failed to validate");
        }

        committer = new GeneralHashCommitter(new SHA1Digest(), new SecureRandom());

        if (committer.isRevealed(c, data))
        {
            fail("general commitment validated!!");
        }

        c = committer.commit(data);

        // try and fool it.
        byte[] s = c.getSecret();
        byte[] newS = Arrays.copyOfRange(s, 0, s.length - 1);
        byte[] newData = new byte[data.length + 1];

        newData[0] = s[s.length - 1];
        System.arraycopy(data, 0, newData, 1, data.length);

        c = new Commitment(newS, c.getCommitment());

        if (committer.isRevealed(c, newData))
        {
            fail("general commitment validated!!");
        }

        try
        {
            committer.isRevealed(c, new byte[data.length + 1]);
        }
        catch (Exception e)
        {
            if (!e.getMessage().equals("Message and witness secret lengths do not match."))
            {
                fail("exception thrown but wrong message");
            }
        }

        // SHA1 has a block size of 512 bits, try a message that's too big

        try
        {
            c = committer.commit(new byte[33]);
        }
        catch (DataLengthException e)
        {
            if (!e.getMessage().equals("Message to be committed to too large for digest."))
            {
                fail("exception thrown but wrong message");
            }
        }
    }

    public void performTest()
        throws Exception
    {
        performBasicTest();
        performGeneralTest();
    }

    public static void main(String[] args)
    {
        runTest(new HashCommitmentTest());
    }
}
