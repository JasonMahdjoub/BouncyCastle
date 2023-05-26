package com.distrimind.bouncycastle.openpgp.operator.jcajce;

import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import com.distrimind.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import com.distrimind.bouncycastle.jcajce.io.OutputStreamFactory;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;
import com.distrimind.bouncycastle.openpgp.PGPRuntimeOperationException;
import com.distrimind.bouncycastle.openpgp.operator.PGPContentVerifier;
import com.distrimind.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import com.distrimind.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import com.distrimind.bouncycastle.openpgp.operator.PGPDigestCalculator;

public class JcaPGPContentVerifierBuilderProvider
    implements PGPContentVerifierBuilderProvider
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    public JcaPGPContentVerifierBuilderProvider()
    {
    }

    public JcaPGPContentVerifierBuilderProvider setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        keyConverter.setProvider(provider);
        digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaPGPContentVerifierBuilderProvider setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        keyConverter.setProvider(providerName);
        digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
        throws PGPException
    {
        return new JcaPGPContentVerifierBuilder(keyAlgorithm, hashAlgorithm);
    }

    private class JcaPGPContentVerifierBuilder
        implements PGPContentVerifierBuilder
    {
        private int hashAlgorithm;
        private int keyAlgorithm;

        public JcaPGPContentVerifierBuilder(int keyAlgorithm, int hashAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
        }

        public PGPContentVerifier build(final PGPPublicKey publicKey)
            throws PGPException
        {
            final Signature signature = helper.createSignature(keyAlgorithm, hashAlgorithm);
            final PGPDigestCalculator digestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
            final PublicKey jcaKey = keyConverter.getPublicKey(publicKey);

            try
            {
                signature.initVerify(jcaKey);
            }
            catch (InvalidKeyException e)
            {
                throw new PGPException("invalid key.", e);
            }

            return new PGPContentVerifier()
            {
                public int getHashAlgorithm()
                {
                    return hashAlgorithm;
                }

                public int getKeyAlgorithm()
                {
                    return keyAlgorithm;
                }

                public long getKeyID()
                {
                    return publicKey.getKeyID();
                }

                public boolean verify(byte[] expected)
                {
                    try
                    {
                        // an RSA PGP signature is stored as an MPI, this can occasionally result in a short
                        // signature if there is a leading zero.
                        if (jcaKey instanceof RSAPublicKey)
                        {
                            int modLength = (((RSAPublicKey)jcaKey).getModulus().bitLength() + 7) / 8;
                            if (expected.length < modLength)
                            {
                                byte[] tmp = new byte[modLength];

                                System.arraycopy(expected, 0, tmp, tmp.length - expected.length, expected.length);
           
                                return signature.verify(tmp);
                            }
                        }
                        if (keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY)
                        {
                            signature.update(digestCalculator.getDigest());
                            
                            return signature.verify(expected);
                        }
                        return signature.verify(expected);
                    }
                    catch (SignatureException e)
                    {
                        throw new PGPRuntimeOperationException("unable to verify signature: " + e.getMessage(), e);
                    }
                }

                public OutputStream getOutputStream()
                {
                    if (keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY)
                    {
                         return digestCalculator.getOutputStream();
                    }
                    return OutputStreamFactory.createStream(signature);
                }
            };
        }
    }
}
