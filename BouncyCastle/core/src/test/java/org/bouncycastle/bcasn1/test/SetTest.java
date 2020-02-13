package org.bouncycastle.bcasn1.test;

import org.bouncycastle.bcasn1.ASN1Boolean;
import org.bouncycastle.bcasn1.ASN1EncodableVector;
import org.bouncycastle.bcasn1.ASN1Integer;
import org.bouncycastle.bcasn1.ASN1Set;
import org.bouncycastle.bcasn1.ASN1TaggedObject;
import org.bouncycastle.bcasn1.BERSet;
import org.bouncycastle.bcasn1.DERBitString;
import org.bouncycastle.bcasn1.DEROctetString;
import org.bouncycastle.bcasn1.DERSequence;
import org.bouncycastle.bcasn1.DERSet;
import org.bouncycastle.bcasn1.DERTaggedObject;
import org.bouncycastle.bcutil.test.SimpleTest;

/**
 * Set sorting test example
 */
public class SetTest
    extends SimpleTest
{

    public String getName()
    {
        return "Set";
    }

    private void checkedSortedSet(int attempt, ASN1Set s)
    {
        if (s.getObjectAt(0) instanceof ASN1Boolean
            && s.getObjectAt(1) instanceof ASN1Integer
            && s.getObjectAt(2) instanceof DERBitString
            && s.getObjectAt(3) instanceof DEROctetString)
        {
            return;
        }

        fail("sorting failed on attempt: " + attempt);
    }

    public void performTest()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        byte[] data = new byte[10];

        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));

        checkedSortedSet(0, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));

        checkedSortedSet(1, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(ASN1Boolean.getInstance(true));
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new ASN1Integer(100));


        checkedSortedSet(2, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new DERBitString(data));
        v.add(new DEROctetString(data));
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));

        checkedSortedSet(3, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));

        ASN1Set s = new BERSet(v);

        if (!(s.getObjectAt(0) instanceof DEROctetString))
        {
            fail("BER set sort order changed.");
        }

        // create an implicitly tagged "set" without sorting
        ASN1TaggedObject tag = new DERTaggedObject(false, 1, new DERSequence(v));
        s = ASN1Set.getInstance(tag, false);

        if (s.getObjectAt(0) instanceof ASN1Boolean)
        {
            fail("sorted when shouldn't be.");
        }

        // equality test
        v = new ASN1EncodableVector();

        v.add(ASN1Boolean.getInstance(true));
        v.add(ASN1Boolean.getInstance(true));
        v.add(ASN1Boolean.getInstance(true));

        s = new DERSet(v);
    }

    public static void main(
        String[]    args)
    {
        runTest(new SetTest());
    }
}
