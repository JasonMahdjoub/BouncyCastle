package com.distrimind.bouncycastle.jcajce.provider.asymmetric;

import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

/**
 * For some reason the class path project thinks that such a KeyFactory will exist.
 */
public class X509
{
    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {

        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.X.509", "com.distrimind.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory");
            provider.addAlgorithm("Alg.Alias.KeyFactory.X509", "X.509");

            //
            // certificate factories.
            //
            provider.addAlgorithm("CertificateFactory.X.509", "com.distrimind.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory");
            provider.addAlgorithm("Alg.Alias.CertificateFactory.X509", "X.509");
        }
    }
}
