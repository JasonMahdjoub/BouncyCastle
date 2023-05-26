package com.distrimind.bouncycastle.asn1.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.util.test.SimpleTestResult;
import com.distrimind.bouncycastle.test.PrintTestResult;

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

        PrintTestResult.printResult( junit.textui.TestRunner.run(suite()));
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("ASN.1 Tests");

        suite.addTestSuite(OctetStringTest.class);
        suite.addTestSuite(ParseTest.class);
        
        return suite;
    }
}
