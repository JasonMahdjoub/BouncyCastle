package com.distrimind.bouncycastle.tsp.test;

import java.io.InputStream;
import java.util.Date;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.distrimind.bouncycastle.tsp.ers.ERSEvidenceRecord;
import com.distrimind.bouncycastle.tsp.ers.ERSInputStreamData;
import com.distrimind.bouncycastle.util.io.Streams;

public class ERSTestdatenTest
    extends TestCase
{
    public void testChain1ATS()
        throws Exception
    {
        ERSEvidenceRecord ers = new ERSEvidenceRecord(Streams.readAll(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain1ATS/BIN_ER.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));

        ers.validatePresent(new ERSInputStreamData(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain1ATS/BIN.bin")), new Date());
    }

    public void testChain2ATS()
        throws Exception
    {
        ERSEvidenceRecord ers = new ERSEvidenceRecord(Streams.readAll(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain2ATS/BIN_ER.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));

        ers.validatePresent(new ERSInputStreamData(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain2ATS/BIN.bin")), new Date());

        ers = new ERSEvidenceRecord(Streams.readAll(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain2ATS/testRenewal.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));
    }

    public void test2Chains3ATS()
        throws Exception
    {
        ERSEvidenceRecord ers = new ERSEvidenceRecord(Streams.readAll(getTestData("Testdaten_ERS-Testool/rfc4998/2Chains3ATS/BIN_ER.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));

        ers.validatePresent(new ERSInputStreamData(getTestData("Testdaten_ERS-Testool/rfc4998/2Chains3ATS/BIN.bin")), new Date());
    }

    private static InputStream getTestData(String resource)
    {
        return ERSTestdatenTest.class.getResourceAsStream("20170316_Testdaten/" + resource);
    }
}