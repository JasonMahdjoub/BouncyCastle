package com.distrimind.bouncycastle.jsse.provider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;

import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;

class ProvKeyManagerFactorySpi
    extends KeyManagerFactorySpi
{
    private static final Logger LOG = Logger.getLogger(ProvKeyManagerFactorySpi.class.getName());

    static KeyStoreConfig getDefaultKeyStore() throws Exception
    {
        String defaultType = KeyStore.getDefaultType();

        String ksPath = null;
        char[] ksPassword = null;

        String ksPathProp = PropertyUtils.getSystemProperty("javax.net.ssl.keyStore");
        if ("NONE".equals(ksPathProp))
        {
            // Do not try to load any file
        }
        else if (null != ksPathProp)
        {
            if (new File(ksPathProp).exists())
            {
                ksPath = ksPathProp;
            }
        }

        KeyStore ks = createKeyStore(defaultType);

        String ksPasswordProp = PropertyUtils.getSystemProperty("javax.net.ssl.keyStorePassword");
        if (null != ksPasswordProp)
        {
            ksPassword = ksPasswordProp.toCharArray();
        }

        InputStream ksInput = null;
        try
        {
            if (null == ksPath)
            {
                LOG.info("Initializing empty key store");
            }
            else
            {
                LOG.info("Initializing with key store at path: " + ksPath);
                ksInput = new BufferedInputStream(new FileInputStream(ksPath));
            }

            ks.load(ksInput, ksPassword);
        }
        finally
        {
            if (null != ksInput)
            {
                ksInput.close();
            }
        }

        return new KeyStoreConfig(ks, ksPassword);
    }

    protected final JcaJceHelper helper;

    protected X509ExtendedKeyManager x509KeyManager;

    ProvKeyManagerFactorySpi(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    @Override
    protected KeyManager[] engineGetKeyManagers()
    {
        if (null == x509KeyManager)
        {
            throw new IllegalStateException("KeyManagerFactory not initialized");
        }

        return new KeyManager[]{ x509KeyManager };
    }

    @Override
    protected void engineInit(KeyStore ks, char[] ksPassword)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        // NOTE: When key store is null, we do not try to load defaults

        List<KeyStore.Builder> builders = getKeyStoreBuilders(ks, ksPassword);
        this.x509KeyManager = new ProvX509KeyManager(helper, builders);
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
        throws InvalidAlgorithmParameterException
    {
        if (managerFactoryParameters instanceof KeyStoreBuilderParameters)
        {
            List<KeyStore.Builder> builders = ((KeyStoreBuilderParameters)managerFactoryParameters).getParameters();
            this.x509KeyManager = new ProvX509KeyManager(helper, builders);
        }
        else
        {
            throw new InvalidAlgorithmParameterException("Parameters must be instance of KeyStoreBuilderParameters");
        }
    }

    private static KeyStore createKeyStore(String defaultType)
        throws NoSuchProviderException, KeyStoreException
    {
        String ksType = getKeyStoreType(defaultType);
        String ksProv = PropertyUtils.getSystemProperty("javax.net.ssl.keyStoreProvider");
        return (null == ksProv || ksProv.length() < 1)
            ?   KeyStore.getInstance(ksType)
            :   KeyStore.getInstance(ksType, ksProv);
    }

    private static List<KeyStore.Builder> getKeyStoreBuilders(KeyStore ks, char[] ksPassword)
        throws KeyStoreException
    {
        if (null == ks)
        {
            return Collections.emptyList();
        }

        try
        {
            KeyStore.Builder builder = KeyStore.Builder.newInstance(ks, new KeyStore.PasswordProtection(ksPassword));

            return Collections.singletonList(builder);
        }
        catch (RuntimeException e)
        {
            throw new KeyStoreException("initialization failed", e);
        }
    }

    private static String getKeyStoreType(String defaultType)
    {
        String ksType = PropertyUtils.getSystemProperty("javax.net.ssl.keyStoreType");
        return (null == ksType) ? defaultType : ksType;
    }
}
