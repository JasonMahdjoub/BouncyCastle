package org.bouncycastle.bcasn1.test;

import org.bouncycastle.bcasn1.ASN1Integer;
import org.bouncycastle.bcasn1.DERSequence;
import org.bouncycastle.bcasn1.cmc.BodyPartID;
import org.bouncycastle.bcasn1.cmc.LraPopWitness;
import org.bouncycastle.bcutil.Arrays;
import org.bouncycastle.bcutil.test.SimpleTest;


public class LraPopWitnessTest
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new LraPopWitnessTest());
    }

    public String getName()
    {
        return "LraPopWitnessTest";
    }

    public void performTest()
        throws Exception
    {
        LraPopWitness popWitness = new LraPopWitness(new BodyPartID(10L), new DERSequence(new ASN1Integer(20L)));
        byte[] b = popWitness.getEncoded();
        LraPopWitness popWitnessResult = LraPopWitness.getInstance(b);

        isTrue("BodyIds", Arrays.areEqual(popWitness.getBodyIds(), popWitnessResult.getBodyIds()));
        isEquals("PkiDataBody", popWitness.getPkiDataBodyid(), popWitnessResult.getPkiDataBodyid());

        try {
            LraPopWitness.getInstance(new DERSequence());
            fail("Sequence length must be 2");
        } catch (Throwable t) {
            isEquals("Exception class",t.getClass(), IllegalArgumentException.class);
        }
    }
}
