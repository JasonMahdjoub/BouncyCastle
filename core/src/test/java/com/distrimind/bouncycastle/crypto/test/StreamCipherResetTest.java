package com.distrimind.bouncycastle.crypto.test;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.crypto.StreamCipher;
import com.distrimind.bouncycastle.crypto.engines.ChaChaEngine;
import com.distrimind.bouncycastle.crypto.engines.Grain128Engine;
import com.distrimind.bouncycastle.crypto.engines.Grainv1Engine;
import com.distrimind.bouncycastle.crypto.engines.HC128Engine;
import com.distrimind.bouncycastle.crypto.engines.HC256Engine;
import com.distrimind.bouncycastle.crypto.engines.ISAACEngine;
import com.distrimind.bouncycastle.crypto.engines.RC4Engine;
import com.distrimind.bouncycastle.crypto.engines.Salsa20Engine;
import com.distrimind.bouncycastle.crypto.engines.XSalsa20Engine;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.crypto.params.ParametersWithIV;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;

/**
 * Test whether block ciphers implement reset contract on init, encrypt/decrypt and reset.
 */
public class StreamCipherResetTest
    extends SimpleTest
{
    public String getName()
    {
        return "Stream Cipher Reset";
    }

    public void performTest()
        throws Exception
    {
        testReset(new Salsa20Engine(), new Salsa20Engine(), new ParametersWithIV(new KeyParameter(random(32)), random(8)));
        testReset(new Salsa20Engine(), new Salsa20Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(8)));
        testReset(new XSalsa20Engine(), new XSalsa20Engine(), new ParametersWithIV(new KeyParameter(random(32)), random(24)));
        testReset(new ChaChaEngine(), new ChaChaEngine(), new ParametersWithIV(new KeyParameter(random(32)), random(8)));
        testReset(new ChaChaEngine(), new ChaChaEngine(), new ParametersWithIV(new KeyParameter(random(16)), random(8)));
        testReset(new RC4Engine(), new RC4Engine(), new KeyParameter(random(16)));
        testReset(new ISAACEngine(), new ISAACEngine(), new KeyParameter(random(16)));
        testReset(new HC128Engine(), new HC128Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(16)));
        testReset(new HC256Engine(), new HC256Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(16)));
        testReset(new Grainv1Engine(), new Grainv1Engine(), new ParametersWithIV(new KeyParameter(random(10)), random(8)));
        testReset(new Grain128Engine(), new Grain128Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(12)));
    }

    private static final SecureRandom RAND = new SecureRandom();

    private byte[] random(int size)
    {
        final byte[] data = new byte[size];
        RAND.nextBytes(data);
        return data;
    }

    private void testReset(StreamCipher cipher1, StreamCipher cipher2, CipherParameters params)
        throws InvalidCipherTextException
    {
        cipher1.init(true, params);

        byte[] plaintext = new byte[1023];
        byte[] ciphertext = new byte[plaintext.length];

        // Establish baseline answer
        cipher1.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);

        // Test encryption resets
        checkReset(cipher1, params, true, plaintext, ciphertext);

        // Test decryption resets with fresh instance
        cipher2.init(false, params);
        checkReset(cipher2, params, false, ciphertext, plaintext);
    }

    private void checkReset(StreamCipher cipher,
                            CipherParameters params,
                            boolean encrypt,
                            byte[] pretext,
                            byte[] posttext)
        throws InvalidCipherTextException
    {
        // Do initial run
        byte[] output = new byte[posttext.length];
        cipher.processBytes(pretext, 0, pretext.length, output, 0);

        // Check encrypt resets cipher
        cipher.init(encrypt, params);

        try
        {
            cipher.processBytes(pretext, 0, pretext.length, output, 0);
        }
        catch (Exception e)
        {
            fail(cipher.getAlgorithmName() + " init did not reset: " + e.getMessage());
        }
        if (!Arrays.areEqual(output, posttext))
        {
            fail(cipher.getAlgorithmName() + " init did not reset.", new String(Hex.encode(posttext)),
                new String(Hex.encode(output)));
        }

        // Check reset resets data
        cipher.reset();

        try
        {
            cipher.processBytes(pretext, 0, pretext.length, output, 0);
        }
        catch (Exception e)
        {
            fail(cipher.getAlgorithmName() + " reset did not reset: " + e.getMessage());
        }
        if (!Arrays.areEqual(output, posttext))
        {
            fail(cipher.getAlgorithmName() + " reset did not reset.");
        }
    }

    public static void main(String[] args)
    {
        runTest(new StreamCipherResetTest());
    }

}
