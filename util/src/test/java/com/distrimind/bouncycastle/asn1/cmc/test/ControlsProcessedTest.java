package com.distrimind.bouncycastle.asn1.cmc.test;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.DERUTF8String;
import com.distrimind.bouncycastle.asn1.cmc.BodyPartID;
import com.distrimind.bouncycastle.asn1.cmc.BodyPartReference;
import com.distrimind.bouncycastle.asn1.cmc.ControlsProcessed;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class ControlsProcessedTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new ControlsProcessedTest());
    }

    public String getName()
    {
        return "ControlsProcessedTest";
    }

    public void performTest()
        throws Exception
    {
        ControlsProcessed cp = new ControlsProcessed(new BodyPartReference[]{new BodyPartReference(new BodyPartID(12L)), new BodyPartReference(new BodyPartID(14L))});
        byte[] b = cp.getEncoded();
        ControlsProcessed cpResult = ControlsProcessed.getInstance(b);
        isTrue(cpResult.getBodyList().length == cp.getBodyList().length);
        isEquals(cpResult.getBodyList()[0], cp.getBodyList()[0]);
        isEquals(cpResult.getBodyList()[1], cp.getBodyList()[1]);

        //
        // Incorrect sequence size.
        //

        try
        {
            ControlsProcessed.getInstance(new DERSequence(
                new ASN1Encodable[]{new ASN1Integer(12L), new DERUTF8String("Monkeys")
                }));
            fail("Must accept only sequence length of 1");
        }
        catch (Throwable t)
        {
            isEquals(t.getClass(), IllegalArgumentException.class);
        }
    }

}
