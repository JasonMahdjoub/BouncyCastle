package org.bouncycastle.bcasn1.test;

import org.bouncycastle.bcasn1.DERSequence;
import org.bouncycastle.bcasn1.DERUTF8String;
import org.bouncycastle.bcasn1.cmc.BodyPartID;
import org.bouncycastle.bcasn1.cmc.TaggedContentInfo;
import org.bouncycastle.bcasn1.cms.ContentInfo;
import org.bouncycastle.bcasn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.bcutil.test.SimpleTest;

public class TaggedContentInfoTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new TaggedContentInfoTest());
    }

    public String getName()
    {
        return "TaggedContentInfoTest";
    }

    public void performTest()
        throws Exception
    {
        TaggedContentInfo tci = new TaggedContentInfo(
            new BodyPartID(10L),
            new ContentInfo(PKCSObjectIdentifiers.pkcs_9_at_contentType, new DERUTF8String("Cats")));

        byte[] b = tci.getEncoded();

        TaggedContentInfo tciResp = TaggedContentInfo.getInstance(b);

        isEquals("bodyPartID", tci.getBodyPartID(), tciResp.getBodyPartID());
        isEquals("contentInfo", tci.getContentInfo(), tciResp.getContentInfo());

        try
        {
            TaggedContentInfo.getInstance(new DERSequence());
            fail("Sequence must be 2");
        }
        catch (Throwable t)
        {
            isEquals("Exception type", t.getClass(), IllegalArgumentException.class);
        }

    }
}
