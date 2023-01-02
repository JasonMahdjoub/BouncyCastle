package com.distrimind.bouncycastle.pqc.legacy.crypto.test;


import java.math.BigInteger;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.digests.SHA224Digest;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bouncycastle.pqc.crypto.DigestingMessageSigner;
import com.distrimind.bouncycastle.pqc.legacy.crypto.rainbow.RainbowKeyGenerationParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.rainbow.RainbowKeyPairGenerator;
import com.distrimind.bouncycastle.pqc.legacy.crypto.rainbow.RainbowParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.rainbow.RainbowSigner;
import com.distrimind.bouncycastle.util.BigIntegers;
import com.distrimind.bouncycastle.util.test.SimpleTest;


public class RainbowSignerTest
extends SimpleTest
{
    public String getName()
    {
        return "Rainbow";
    }

    public void performTest()
    {
        RainbowParameters params = new RainbowParameters();

        RainbowKeyPairGenerator rainbowKeyGen = new RainbowKeyPairGenerator();
        RainbowKeyGenerationParameters genParam = new RainbowKeyGenerationParameters(new SecureRandom(), params);

        rainbowKeyGen.init(genParam);

        AsymmetricCipherKeyPair pair = rainbowKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), new SecureRandom());

        DigestingMessageSigner rainbowSigner = new DigestingMessageSigner(new RainbowSigner() , new SHA224Digest());

        rainbowSigner.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        rainbowSigner.update(message, 0, message.length);
        byte[] sig = rainbowSigner.generateSignature();

        rainbowSigner.init(false, pair.getPublic());
        rainbowSigner.update(message, 0, message.length);

        if (!rainbowSigner.verifySignature(sig))
        {
            fail("verification fails");
        }
    }

    public static void main(
            String[]    args)
    {
        runTest(new RainbowSignerTest());
    }
}
