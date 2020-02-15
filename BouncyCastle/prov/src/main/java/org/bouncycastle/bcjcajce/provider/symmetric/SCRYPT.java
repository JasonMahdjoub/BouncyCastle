package org.bouncycastle.bcjcajce.provider.symmetric;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;

import org.bouncycastle.bcasn1.misc.BCMiscObjectIdentifiers;
import org.bouncycastle.bccrypto.CipherParameters;
import org.bouncycastle.bccrypto.PasswordConverter;
import org.bouncycastle.bccrypto.generators.SCrypt;
import org.bouncycastle.bccrypto.params.KeyParameter;
import org.bouncycastle.bcjcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.bcjcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.bcjcajce.spec.ScryptKeySpec;

public class SCRYPT
{
    private SCRYPT()
    {

    }

    public static class BasePBKDF2
        extends BaseSecretKeyFactory
    {
        private int scheme;

        public BasePBKDF2(String name, int scheme)
        {
            super(name, BCMiscObjectIdentifiers.id_scrypt);

            this.scheme = scheme;
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof ScryptKeySpec)
            {
                ScryptKeySpec pbeSpec = (ScryptKeySpec)keySpec;

                if (pbeSpec.getSalt() == null)
                {
                    throw new IllegalArgumentException("Salt S must be provided.");
                }
                if (pbeSpec.getCostParameter() <= 1)
                {
                    throw new IllegalArgumentException("Cost parameter N must be > 1.");
                }

                if (pbeSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("positive key length required: "
                        + pbeSpec.getKeyLength());
                }

                if (pbeSpec.getPassword().length == 0)
                {
                    throw new IllegalArgumentException("password empty");
                }

                CipherParameters param = new KeyParameter(SCrypt.generate(
                        PasswordConverter.UTF8.convert(pbeSpec.getPassword()), pbeSpec.getSalt(),
                        pbeSpec.getCostParameter(), pbeSpec.getBlockSize(), pbeSpec.getParallelizationParameter(),
                        pbeSpec.getKeyLength() / 8));

                return new BCPBEKey(this.algName, pbeSpec, param);
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    public static class ScryptWithUTF8
        extends BasePBKDF2
    {
        public ScryptWithUTF8()
        {
            super("SCRYPT", PKCS5S2_UTF8);
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = SCRYPT.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecretKeyFactory.SCRYPT", PREFIX + "$ScryptWithUTF8");
            provider.addAlgorithm("SecretKeyFactory", BCMiscObjectIdentifiers.id_scrypt, PREFIX + "$ScryptWithUTF8");
        }
    }
}
