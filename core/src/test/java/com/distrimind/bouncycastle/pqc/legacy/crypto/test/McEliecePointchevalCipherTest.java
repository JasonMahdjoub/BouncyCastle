package com.distrimind.bouncycastle.pqc.legacy.crypto.test;

import java.security.SecureRandom;
import java.util.Random;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA256Digest;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bouncycastle.pqc.legacy.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import com.distrimind.bouncycastle.pqc.legacy.crypto.mceliece.McElieceCCA2Parameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.mceliece.McEliecePointchevalCipher;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class McEliecePointchevalCipherTest
    extends SimpleTest
{
    SecureRandom keyRandom = new SecureRandom();

    public String getName()
    {
        return "McElieceFujisaki";

    }

    public void performTest()
        throws Exception
    {
        int numPassesKPG = 1;
        int numPassesEncDec = 10;
        Random rand = new Random();
        byte[] mBytes;
        for (int j = 0; j < numPassesKPG; j++)
        {

            McElieceCCA2Parameters params = new McElieceCCA2Parameters("SHA-256");
            McElieceCCA2KeyPairGenerator mcElieceCCA2KeyGen = new McElieceCCA2KeyPairGenerator();
            McElieceCCA2KeyGenerationParameters genParam = new McElieceCCA2KeyGenerationParameters(keyRandom, params);

            mcElieceCCA2KeyGen.init(genParam);
            AsymmetricCipherKeyPair pair = mcElieceCCA2KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);
            Digest msgDigest = new SHA256Digest();
            McEliecePointchevalCipher mcEliecePointchevalDigestCipher = new McEliecePointchevalCipher();


            for (int k = 1; k <= numPassesEncDec; k++)
            {
                System.out.println("############### test: " + k);
                // initialize for encryption
                mcEliecePointchevalDigestCipher.init(true, param);

                // generate random message
                int mLength = (rand.nextInt() & 0x1f) + 1;
                mBytes = new byte[mLength];
                rand.nextBytes(mBytes);

                msgDigest.update(mBytes, 0, mBytes.length);
                byte[] hash = new byte[msgDigest.getDigestSize()];
                msgDigest.doFinal(hash, 0);

                // encrypt
                byte[] enc = mcEliecePointchevalDigestCipher.messageEncrypt(hash);

                // initialize for decryption
                mcEliecePointchevalDigestCipher.init(false, pair.getPrivate());
                byte[] constructedmessage = mcEliecePointchevalDigestCipher.messageDecrypt(enc);

                // XXX write in McElieceFujisakiDigestCipher?

                boolean verified = true;
                for (int i = 0; i < hash.length; i++)
                {
                    verified = verified && hash[i] == constructedmessage[i];
                }

                if (!verified)
                {
                    fail("en/decryption fails");
                }
                else
                {
                    System.out.println("test okay");
                    System.out.println();
                }

            }
        }

    }

    public static void main(
        String[] args)
    {
        runTest(new McEliecePointchevalCipherTest());
    }

}
