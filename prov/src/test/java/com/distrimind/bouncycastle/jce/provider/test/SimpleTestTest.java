package com.distrimind.bouncycastle.jce.provider.test;

import com.distrimind.bouncycastle.util.test.Test;
import junit.framework.TestCase;
import com.distrimind.bouncycastle.util.test.SimpleTestResult;

public class SimpleTestTest
    extends TestCase
{
    public void testJCE()
    {
        Test[] tests = RegressionTest.tests;

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                System.err.println(tests[i].getClass());
                fail("index " + i + " " + result);
            }
        }
    }
}
