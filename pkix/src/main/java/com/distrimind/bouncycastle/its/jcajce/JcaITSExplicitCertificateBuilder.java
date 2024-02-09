package com.distrimind.bouncycastle.its.jcajce;

import java.security.Provider;
import java.security.interfaces.ECPublicKey;

import com.distrimind.bouncycastle.its.operator.ITSContentSigner;
import com.distrimind.bouncycastle.its.ITSCertificate;
import com.distrimind.bouncycastle.its.ITSExplicitCertificateBuilder;
import com.distrimind.bouncycastle.its.ITSPublicEncryptionKey;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;

public class JcaITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    private JcaJceHelper helper;

    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public JcaITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        this(signer, tbsCertificate, new DefaultJcaJceHelper());
    }

    private JcaITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate, JcaJceHelper helper)
    {
        super(signer, tbsCertificate);
        this.helper = helper;
    }

    public JcaITSExplicitCertificateBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }

    public JcaITSExplicitCertificateBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);
        return this;
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKey verificationKey)
    {
        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKey verificationKey,
        ECPublicKey encryptionKey)
    {
        ITSPublicEncryptionKey publicEncryptionKey = null;
        if (encryptionKey != null)
        {
            publicEncryptionKey = new JceITSPublicEncryptionKey(encryptionKey, helper);
        }

        return super.build(certificateId, new JcaITSPublicVerificationKey(verificationKey, helper), publicEncryptionKey);
    }
}
