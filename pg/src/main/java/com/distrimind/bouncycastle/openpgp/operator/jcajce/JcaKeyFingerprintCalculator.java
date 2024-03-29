package com.distrimind.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import com.distrimind.bouncycastle.bcpg.BCPGKey;
import com.distrimind.bouncycastle.bcpg.MPInteger;
import com.distrimind.bouncycastle.bcpg.PublicKeyPacket;
import com.distrimind.bouncycastle.bcpg.RSAPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.UnsupportedPacketVersionException;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;

public class JcaKeyFingerprintCalculator
    implements KeyFingerPrintCalculator
{
    private final JcaJceHelper helper;

    /**
     * Base Constructor - use the JCA defaults.
     */
    public JcaKeyFingerprintCalculator()
    {
        this(new DefaultJcaJceHelper());
    }

    private JcaKeyFingerprintCalculator(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param provider the JCA provider to use.
     * @return a new JceKeyFingerprintCalculator supported by the passed in provider.
     */
    public JcaKeyFingerprintCalculator setProvider(Provider provider)
    {
        return new JcaKeyFingerprintCalculator(new ProviderJcaJceHelper(provider));
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param providerName the name of the JCA provider to use.
     * @return a new JceKeyFingerprintCalculator supported by the passed in named provider.
     */
    public JcaKeyFingerprintCalculator setProvider(String providerName)
    {
        return new JcaKeyFingerprintCalculator(new NamedJcaJceHelper(providerName));
    }

    public byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException
    {
        BCPGKey key = publicPk.getKey();

        if (publicPk.getVersion() <= 3)
        {
            RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

            try
            {
                MessageDigest digest = helper.createMessageDigest("MD5");

                byte[] bytes = new MPInteger(rK.getModulus()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);

                bytes = new MPInteger(rK.getPublicExponent()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);

                return digest.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new PGPException("can't find MD5", e);
            }
            catch (NoSuchProviderException e)
            {
                throw new PGPException("can't find MD5", e);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else if (publicPk.getVersion() == 4)
        {
            try
            {
                byte[] kBytes = publicPk.getEncodedContents();

                MessageDigest digest = helper.createMessageDigest("SHA1");

                digest.update((byte)0x99);
                digest.update((byte)(kBytes.length >> 8));
                digest.update((byte)kBytes.length);
                digest.update(kBytes);

                return digest.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new PGPException("can't find SHA1", e);
            }
            catch (NoSuchProviderException e)
            {
                throw new PGPException("can't find SHA1", e);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else if (publicPk.getVersion() == 6)
        {
            try
            {
                byte[] kBytes = publicPk.getEncodedContents();

                MessageDigest digest = helper.createMessageDigest("SHA-256");

                digest.update((byte)0x9b);

                digest.update((byte)(kBytes.length >> 24));
                digest.update((byte)(kBytes.length >> 16));
                digest.update((byte)(kBytes.length >> 8));
                digest.update((byte)kBytes.length);

                digest.update(kBytes);

                return digest.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new PGPException("can't find SHA-256", e);
            }
            catch (NoSuchProviderException e)
            {
                throw new PGPException("can't find SHA-256", e);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported PGP key version: " + publicPk.getVersion());
        }
    }
}
