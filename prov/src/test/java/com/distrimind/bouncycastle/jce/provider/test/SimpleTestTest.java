package com.distrimind.bouncycastle.jce.provider.test;

import java.security.Security;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.util.test.SimpleTestResult;

public class SimpleTestTest
    extends TestCase
{
    public void testJCE()
    {

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        com.distrimind.bouncycastle.util.test.Test[] tests = RegressionTest.tests;

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                fail("index " + i + " " + result.toString());
            }
        }
    }
}
