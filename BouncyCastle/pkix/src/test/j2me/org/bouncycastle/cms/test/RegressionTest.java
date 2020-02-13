package org.bouncycastle.cms.test;

import org.bouncycastle.bcutil.test.SimpleTest;
import org.bouncycastle.bcutil.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new BcEnvelopedDataTest(),
        new BcSignedDataTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
