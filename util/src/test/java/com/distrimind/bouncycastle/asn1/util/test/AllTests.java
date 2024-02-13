package com.distrimind.bouncycastle.asn1.util.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.asn1.cms.test.OctetStringTest;
import com.distrimind.bouncycastle.asn1.cms.test.ParseTest;
import com.distrimind.bouncycastle.asn1.misc.test.GetInstanceTest;
import com.distrimind.bouncycastle.test.PrintTestResult;
import com.distrimind.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public void testASN1()
    {   
        com.distrimind.bouncycastle.util.test.Test[] tests = RegressionTest.tests;
        
        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult  result = (SimpleTestResult)tests[i].perform();
            
            if (!result.isSuccessful())
            {
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
        TestSuite suite = new TestSuite("ASN.1 Tests");
        
        suite.addTestSuite(AllTests.class);
        suite.addTestSuite(OctetStringTest.class);
        suite.addTestSuite(ParseTest.class);
        suite.addTestSuite(GetInstanceTest.class);
        
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
