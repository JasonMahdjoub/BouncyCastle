package com.distrimind.bouncycastle.pqc.crypto.test;

import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new Sphincs256Test(),
        new NewHopeTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
