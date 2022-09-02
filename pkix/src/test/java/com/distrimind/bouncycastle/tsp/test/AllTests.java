package com.distrimind.bouncycastle.tsp.test;

import java.security.Security;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("TSP Tests");
        
        suite.addTestSuite(ParseTest.class);
        suite.addTestSuite(PQCTSPTest.class);
        suite.addTestSuite(NewTSPTest.class);
        suite.addTestSuite(CMSTimeStampedDataTest.class);
        suite.addTestSuite(CMSTimeStampedDataParserTest.class);
        suite.addTestSuite(CMSTimeStampedDataGeneratorTest.class);
        suite.addTestSuite(GenTimeAccuracyUnitTest.class);
        suite.addTestSuite(TimeStampTokenInfoUnitTest.class);
        suite.addTestSuite(ERSTest.class);

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
