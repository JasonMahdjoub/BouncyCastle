package com.distrimind.bouncycastle.asn1.cmc.test;

import java.util.Random;

import com.distrimind.bouncycastle.asn1.cmc.BodyPartID;
import com.distrimind.bouncycastle.asn1.cmc.BodyPartPath;
import com.distrimind.bouncycastle.asn1.cmc.BodyPartReference;
import com.distrimind.bouncycastle.util.test.SimpleTest;


public class BodyPartReferenceTest
    extends SimpleTest
{

    public String getName()
    {
        return "BodyPartReferenceTest";
    }

    public void performTest()
        throws Exception
    {
        Random rand = new Random();
        BodyPartReference ch0 = null;
        BodyPartReference ch1 = null;
        {
            // Choice 1
            BodyPartID id = new BodyPartID(Math.abs(rand.nextLong() % 4294967295L));

            ch0 = new BodyPartReference(id);
            byte[] b = ch0.getEncoded();

            BodyPartReference brRes = BodyPartReference.getInstance(b);
            isEquals(brRes, ch0);
        }

        {
            // Choice 2

            BodyPartID[] bpid = new BodyPartID[Math.abs(rand.nextInt()) % 20];
            for (int t = 0; t < bpid.length; t++)
            {
                bpid[t] = new BodyPartID(Math.abs(rand.nextLong() % 4294967295L));
            }

            ch1 = new BodyPartReference(new BodyPartPath(bpid));
            byte[] b = ch1.getEncoded();

            BodyPartReference brRes = BodyPartReference.getInstance(b);
            isEquals(brRes, ch1);
        }


        {
            // Test choice alternatives are not equal.
            BodyPartID id = new BodyPartID(Math.abs(rand.nextLong() % 4294967295L));

            ch0 = new BodyPartReference(id);
            ch1 = new BodyPartReference(new BodyPartPath(id));

            try
            {
                isEquals(ch0, ch1);
                fail("Must not be equal.");
            }
            catch (Throwable t)
            {
                // Ignored
            }
        }

    }

    public static void main(String[] args)
    {
        runTest(new BodyPartReferenceTest());
    }

}
