package com.distrimind.bouncycastle.openpgp.test;

import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new BcPGPDSAElGamalTest(),
        new BcPGPDSATest(),
        new BcPGPKeyRingTest(),
        new BcPGPPBETest(),
        new BcPGPRSATest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
