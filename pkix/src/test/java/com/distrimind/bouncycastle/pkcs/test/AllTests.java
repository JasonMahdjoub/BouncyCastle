package com.distrimind.bouncycastle.pkcs.test;

import com.distrimind.bouncycastle.test.PrintTestResult;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("PKCS Tests");
        
        suite.addTestSuite(PfxPduTest.class);
        suite.addTestSuite(PKCS10Test.class);
        suite.addTestSuite(PKCS8Test.class);
        suite.addTestSuite(PBETest.class);

        return new BCTestSetup(suite);
    }
}
