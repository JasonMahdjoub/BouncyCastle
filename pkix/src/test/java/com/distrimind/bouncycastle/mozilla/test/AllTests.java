package com.distrimind.bouncycastle.mozilla.test;

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
    public void testMozilla()
    {   
        Security.addProvider(new BouncyCastleProvider());
        
        com.distrimind.bouncycastle.util.test.Test[] tests = new com.distrimind.bouncycastle.util.test.Test[] { new SPKACTest() };
        
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
        TestSuite suite = new TestSuite("Mozilla Tests");
        
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

        }

        protected void tearDown()
        {

        }
    }

}
