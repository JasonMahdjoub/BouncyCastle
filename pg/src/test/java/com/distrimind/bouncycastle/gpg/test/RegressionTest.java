package com.distrimind.bouncycastle.gpg.test;

import java.security.Security;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new KeyBoxTest()
    };

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        SimpleTest.runTests(tests);
    }
}
