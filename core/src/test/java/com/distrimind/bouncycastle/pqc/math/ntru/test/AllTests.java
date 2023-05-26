package com.distrimind.bouncycastle.pqc.math.ntru.test;

import com.distrimind.bouncycastle.test.PrintTestResult;
import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("PQ Specific Math Tests");

        suite.addTestSuite(HPSPolynomialTest.class);
        suite.addTestSuite(HRSSPolynomialTest.class);
        suite.addTestSuite(PolynomialTest.class);

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

        }

        protected void tearDown()
        {

        }
    }
}
