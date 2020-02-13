package org.bouncycastle.cert.crmf;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcasn1.ASN1Encoding;
import org.bouncycastle.bcasn1.cmp.PBMParameter;
import org.bouncycastle.bcasn1.crmf.PKMACValue;
import org.bouncycastle.bcasn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.bcutil.Arrays;

class PKMACValueVerifier
{
    private final PKMACBuilder builder;

    public PKMACValueVerifier(PKMACBuilder builder)
    {
        this.builder = builder;
    }

    public boolean isValid(PKMACValue value, char[] password, SubjectPublicKeyInfo keyInfo)
        throws CRMFException
    {
        builder.setParameters(PBMParameter.getInstance(value.getAlgId().getParameters()));
        MacCalculator calculator = builder.build(password);

        OutputStream macOut = calculator.getOutputStream();

        try
        {
            macOut.write(keyInfo.getEncoded(ASN1Encoding.DER));

            macOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFException("exception encoding mac input: " + e.getMessage(), e);
        }

        return Arrays.constantTimeAreEqual(calculator.getMac(), value.getValue().getBytes());
    }
}