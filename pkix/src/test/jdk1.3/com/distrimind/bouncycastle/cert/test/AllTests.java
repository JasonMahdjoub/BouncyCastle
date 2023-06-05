package com.distrimind.bouncycastle.cert.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.util.test.SimpleTestResult;
import com.distrimind.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public void testSimpleTests()
    {
        com.distrimind.bouncycastle.util.test.Test[] tests = new com.distrimind.bouncycastle.util.test.Test[] { new CertTest(), new PKCS10Test(), new AttrCertSelectorTest(), new AttrCertTest(), new X509ExtensionUtilsTest() };

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult  result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                fail(result.toString());
            }
        }
    }

    public static void main (String[] args)
    {
       PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Cert Tests");

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        suite.addTestSuite(AllTests.class);
        suite.addTestSuite(BcAttrCertSelectorTest.class);
        suite.addTestSuite(BcAttrCertSelectorTest.class);
        suite.addTestSuite(BcAttrCertTest.class);
        suite.addTestSuite(BcPKCS10Test.class);
        suite.addTest(ConverterTest.suite());

        return suite;
    }
}