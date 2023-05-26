package com.distrimind.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;

import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPSessionKey;
import com.distrimind.bouncycastle.openpgp.operator.PGPDataDecryptor;
import com.distrimind.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

public class JceSessionKeyDataDecryptorFactoryBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    public JceSessionKeyDataDecryptorFactoryBuilder()
    {
    }

    /**
     * Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider  provider object for cryptographic primitives.
     * @return  the current builder.
     */
    public JceSessionKeyDataDecryptorFactoryBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        keyConverter.setProvider(provider);

        return this;
    }

    /**
     * Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providerName  the name of the provider to reference for cryptographic primitives.
     * @return  the current builder.
     */
    public JceSessionKeyDataDecryptorFactoryBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        keyConverter.setProvider(providerName);

        return this;
    }

    public SessionKeyDataDecryptorFactory build(PGPSessionKey sessionKey)
    {
        return new JceSessionKeyDataDecryptorFactory(helper, sessionKey);
    }

    private static class JceSessionKeyDataDecryptorFactory
        implements SessionKeyDataDecryptorFactory
    {
        private final OperatorHelper helper;
        private final PGPSessionKey sessionKey;

        public JceSessionKeyDataDecryptorFactory(OperatorHelper helper, PGPSessionKey sessionKey)
        {
            this.helper = helper;
            this.sessionKey = sessionKey;
        }

        public PGPSessionKey getSessionKey()
        {
            return sessionKey;
        }

        public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
            throws PGPException
        {
            return helper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
        }

        public PGPDataDecryptor createDataDecryptor(int aeadAlgorithm, byte[] iv, int chunkSize, int encAlgorithm, byte[] key)
            throws PGPException
        {
            return helper.createDataDecryptor(aeadAlgorithm, iv, chunkSize, encAlgorithm, key);
        }
    }
}
