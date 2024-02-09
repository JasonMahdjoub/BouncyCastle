package com.distrimind.bouncycastle.cert.path.test;

import java.security.Security;

import com.distrimind.bouncycastle.test.PrintTestResult;
import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public void testSimpleTests()
    {
        com.distrimind.bouncycastle.util.test.Test[] tests = new com.distrimind.bouncycastle.util.test.Test[] {
            new CertPathTest(), new CertPathValidationTest(), new BasicConstraintsTest(),
                new PKITSBasicConstraintsTest() };

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
        TestSuite suite = new TestSuite("Cert Path Tests");

        suite.addTestSuite(AllTests.class);

        return new BCTestSetup(suite);
    }

    static class BCTestSetup
        extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }

}