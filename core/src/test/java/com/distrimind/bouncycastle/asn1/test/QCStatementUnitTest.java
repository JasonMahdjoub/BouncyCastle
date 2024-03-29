package com.distrimind.bouncycastle.asn1.test;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1InputStream;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.asn1.x509.qualified.QCStatement;
import com.distrimind.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class QCStatementUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "QCStatement";
    }

    public void performTest() 
        throws Exception
    {
        QCStatement mv = new QCStatement(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1);

        checkConstruction(mv, RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1, null);
        
        ASN1Encodable info = new SemanticsInformation(new ASN1ObjectIdentifier("1.2"));
        
        mv = new QCStatement(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1, info);

        checkConstruction(mv, RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1, info);
        
        mv = QCStatement.getInstance(null);
        
        if (mv != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            QCStatement.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
         QCStatement mv,
         ASN1ObjectIdentifier statementId,
         ASN1Encodable statementInfo) 
         throws IOException
    {
        checkStatement(mv, statementId, statementInfo);
        
        mv = QCStatement.getInstance(mv);
        
        checkStatement(mv, statementId, statementInfo);
        
        ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        
        mv = QCStatement.getInstance(seq);
        
        checkStatement(mv, statementId, statementInfo);
    }

    private void checkStatement(
        QCStatement         qcs,
        ASN1ObjectIdentifier statementId,
        ASN1Encodable       statementInfo)
        throws IOException
    {
        if (!qcs.getStatementId().equals(statementId))
        {
            fail("statementIds don't match.");
        }
        
        if (statementInfo != null)
        {
            if (!qcs.getStatementInfo().equals(statementInfo))
            {
                fail("statementInfos don't match.");
            }
        }
        else if (qcs.getStatementInfo() != null)
        {
            fail("statementInfo found when none expected.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new QCStatementUnitTest());
    }
}
