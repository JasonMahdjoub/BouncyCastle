package com.distrimind.bouncycastle.jce.provider.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JCE Tests");

        suite.addTestSuite(SimpleTestTest.class);

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
            System.setProperty("com.distrimind.bouncycastle.bks.enable_v1", "true");

            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }

}
