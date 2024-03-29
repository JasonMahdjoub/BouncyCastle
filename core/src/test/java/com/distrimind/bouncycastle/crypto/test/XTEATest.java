package com.distrimind.bouncycastle.crypto.test;

import com.distrimind.bouncycastle.crypto.engines.XTEAEngine;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;

/**
 * TEA tester - based on C implementation results from https://www.simonshepherd.supanet.com/tea.htm
 */
public class XTEATest
    extends CipherTest
{
    static SimpleTest[]  tests = {
        new BlockCipherVectorTest(0, new XTEAEngine(),
            new KeyParameter(Hex.decode("00000000000000000000000000000000")),
            "0000000000000000",
            "dee9d4d8f7131ed9"),
        new BlockCipherVectorTest(1, new XTEAEngine(),
            new KeyParameter(Hex.decode("00000000000000000000000000000000")),
            "0102030405060708",
            "065c1b8975c6a816"),
        new BlockCipherVectorTest(2, new XTEAEngine(),
            new KeyParameter(Hex.decode("0123456712345678234567893456789A")),
            "0000000000000000",
            "1ff9a0261ac64264"),
        new BlockCipherVectorTest(3, new XTEAEngine(),
            new KeyParameter(Hex.decode("0123456712345678234567893456789A")),
            "0102030405060708",
            "8c67155b2ef91ead"),
            };

    XTEATest()
    {
        super(tests, new XTEAEngine(), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "XTEA";
    }

    public static void main(
        String[]    args)
    {
        runTest(new XTEATest());
    }
}
