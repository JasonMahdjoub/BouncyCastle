
package com.distrimind.bouncycastle.i18n.test;

import com.distrimind.bouncycastle.i18n.filter.test.HTMLFilterTest;
import com.distrimind.bouncycastle.i18n.filter.test.SQLFilterTest;
import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.test.PrintTestResult;

public class AllTests extends TestCase
{

    public static void main (String[] args)
    {
       PrintTestResult.printResult( junit.textui.TestRunner.run (suite()));
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("i18n tests");
        suite.addTestSuite(LocalizedMessageTest.class);
        suite.addTestSuite(HTMLFilterTest.class);
        suite.addTestSuite(SQLFilterTest.class);
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
