package org.bouncycastle.bccrypto.prng.test;

import org.bouncycastle.bcutil.test.SimpleTest;
import org.bouncycastle.bcutil.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new CTRDRBGTest(),
        new DualECDRBGTest(),
        new HashDRBGTest(),
        new HMacDRBGTest(),
        new SP800RandomTest(),
        new X931Test(),
        new FixedSecureRandomTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
