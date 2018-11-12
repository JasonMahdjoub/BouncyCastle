package org.bouncycastle.jcajce.examples;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

public class BcEntropyPoolExample
{
    // Base entropy pool class
    private static class HybridSecureRandom
        extends SecureRandom
    {
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);
        private final SecureRandom baseRandom;
        private final SP800SecureRandom drbg;

        HybridSecureRandom()
        {
            super(null, null);         // stop getDefaultRNG() call

            try
            {
                // JDK 1.7 or below
                // baseRandom = new CoreSecureRandom();
                // JDK 1.8
                baseRandom = SecureRandom.getInstanceStrong();
            }
            catch (Exception e)
            {
                throw new IllegalStateException("unable to create baseRandom: " + e.getMessage(), e);
            }

            drbg = new SP800SecureRandomBuilder(new EntropySourceProvider()
            {
                public EntropySource get(final int bitsRequired)
                {
                    return new SignallingEntropySource(bitsRequired);
                }
            })
            .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
            .buildHash(new SHA512Digest(), baseRandom.generateSeed(32), false);     // 32 byte nonce
        }

        public void setSeed(byte[] seed)
        {
            if (drbg != null)
            {
                drbg.setSeed(seed);
            }
        }

        public void setSeed(long seed)
        {
            if (drbg != null)
            {
                drbg.setSeed(seed);
            }
        }

        public byte[] generateSeed(int numBytes)
        {
            byte[] data = new byte[numBytes];

            // after 20 samples we'll start to check if there is new seed material.
            if (samples.getAndIncrement() > 20)
            {
                if (seedAvailable.getAndSet(false))
                {
                    samples.set(0);
                    drbg.reseed(null);
                }
            }

            drbg.nextBytes(data);

            return data;
        }

        private class SignallingEntropySource
            implements EntropySource
        {
            private final int byteLength;
            private final AtomicReference entropy = new AtomicReference();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);

            SignallingEntropySource(int bitsRequired)
            {
                this.byteLength = (bitsRequired + 7) / 8;
            }

            public boolean isPredictionResistant()
            {
                return true;
            }

            public byte[] getEntropy()
            {
                byte[] seed = (byte[])entropy.getAndSet(null);

                if (seed == null || seed.length != byteLength)
                {
                    seed = baseRandom.generateSeed(byteLength);
                }
                else
                {
                    scheduled.set(false);
                }

                if (!scheduled.getAndSet(true))
                {
                    new Thread(new SignallingEntropySource.EntropyGatherer(byteLength)).start();
                }

                return seed;
            }

            public int entropySize()
            {
                return byteLength * 8;
            }

            private class EntropyGatherer
                implements Runnable
            {
                private final int numBytes;

                EntropyGatherer(int numBytes)
                {
                    this.numBytes = numBytes;
                }

                public void run()
                {
                    entropy.set(baseRandom.generateSeed(numBytes));
                    seedAvailable.set(true);
                }
            }
        }
    }

    // On JDK 1.8 you should be able to replace this with
    // SecureRandom.getInstanceStrong()
    // and avoid the use of the sun.security class.If you're using
    // JDK 1.7 or below you need to use this class.
    private static class CoreSecureRandom
        extends SecureRandom
    {
        CoreSecureRandom()
        {
            super(new sun.security.provider.SecureRandom(), getSunProvider());
        }

        private static Provider getSunProvider()
        {
            try
            {
                Class provClass = Class.forName("sun.security.jca.Providers");

                Method method = provClass.getMethod("getSunProvider");

                return (Provider)method.invoke(provClass);
            }
            catch (Exception e)
            {
                return new sun.security.provider.Sun();
            }
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        // create entropy pool random - note can only be used to seed others
        SecureRandom entropySource = new HybridSecureRandom();

        // create an actual random we can use
        SP800SecureRandom random = new SP800SecureRandomBuilder(entropySource, true)
             .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
             .buildHash(new SHA512Digest(), null, false);

        // add the provider
        Security.addProvider(new BouncyCastleProvider());

        // try it out
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048, random);

        KeyPair kp = kpGen.generateKeyPair();

        System.err.println(kp.getPublic());
    }
}
