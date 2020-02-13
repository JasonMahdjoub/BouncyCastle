package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.bcutil.test.SimpleTest;
import org.bouncycastle.bcutil.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new GMSSSignerTest(),
        new McElieceFujisakiCipherTest(),
        new McElieceKobaraImaiCipherTest(),
        new McElieceCipherTest(),
        new McEliecePointchevalCipherTest(),
        new RainbowSignerTest() ,
        new Sphincs256Test(),
        new NewHopeTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
