package com.distrimind.bouncycastle.openpgp.test;

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
    public void testPGP()
    {   
        Security.addProvider(new BouncyCastleProvider());
        
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
        TestSuite suite = new TestSuite("OpenPGP Tests");
        
        suite.addTestSuite(AllTests.class);
        suite.addTestSuite(DSA2Test.class);

        return suite;
    }
}
