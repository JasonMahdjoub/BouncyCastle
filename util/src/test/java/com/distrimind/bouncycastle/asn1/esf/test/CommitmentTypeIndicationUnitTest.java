package com.distrimind.bouncycastle.asn1.esf.test;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1InputStream;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.esf.CommitmentTypeIdentifier;
import com.distrimind.bouncycastle.asn1.esf.CommitmentTypeIndication;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class CommitmentTypeIndicationUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "CommitmentTypeIndication";
    }

    public void performTest() 
        throws Exception
    {
        CommitmentTypeIndication cti = new CommitmentTypeIndication(CommitmentTypeIdentifier.proofOfOrigin);
        
        checkConstruction(cti, CommitmentTypeIdentifier.proofOfOrigin, null);
        
        ASN1Sequence qualifier = new DERSequence(new ASN1ObjectIdentifier("1.2"));
        
        cti = new CommitmentTypeIndication(CommitmentTypeIdentifier.proofOfOrigin, qualifier);

        checkConstruction(cti, CommitmentTypeIdentifier.proofOfOrigin, qualifier);
        
        cti = CommitmentTypeIndication.getInstance(null);
        
        if (cti != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            CommitmentTypeIndication.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
         CommitmentTypeIndication mv,
         ASN1ObjectIdentifier commitmenttTypeId,
         ASN1Encodable qualifier) 
         throws IOException
    {
        checkStatement(mv, commitmenttTypeId, qualifier);
        
        mv = CommitmentTypeIndication.getInstance(mv);
        
        checkStatement(mv, commitmenttTypeId, qualifier);
        
        ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        
        mv = CommitmentTypeIndication.getInstance(seq);
        
        checkStatement(mv, commitmenttTypeId, qualifier);
    }

    private void checkStatement(
        CommitmentTypeIndication cti,
        ASN1ObjectIdentifier     commitmentTypeId,
        ASN1Encodable           qualifier)
    {
        if (!cti.getCommitmentTypeId().equals(commitmentTypeId))
        {
            fail("commitmentTypeIds don't match.");
        }
        
        if (qualifier != null)
        {
            if (!cti.getCommitmentTypeQualifier().equals(qualifier))
            {
                fail("qualifiers don't match.");
            }
        }
        else if (cti.getCommitmentTypeQualifier() != null)
        {
            fail("qualifier found when none expected.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new CommitmentTypeIndicationUnitTest());
    }
}
