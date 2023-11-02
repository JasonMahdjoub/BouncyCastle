package com.distrimind.bouncycastle.cms.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cms.CMSAttributeTableGenerator;
import com.distrimind.bouncycastle.cms.CMSSignatureEncryptionAlgorithmFinder;
import com.distrimind.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder;
import com.distrimind.bouncycastle.cms.SignerInfoGenerator;
import com.distrimind.bouncycastle.cms.SignerInfoGeneratorBuilder;
import com.distrimind.bouncycastle.operator.ContentSigner;
import com.distrimind.bouncycastle.operator.DigestCalculatorProvider;
import com.distrimind.bouncycastle.operator.OperatorCreationException;

public class JcaSignerInfoGeneratorBuilder
{
    private SignerInfoGeneratorBuilder builder;

    /**
     *  Base constructor.
     *
     * @param digestProvider  a provider of digest calculators for the algorithms required in the signature and attribute calculations.
     */
    public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider)
    {
        this(digestProvider, new DefaultCMSSignatureEncryptionAlgorithmFinder());
    }

    /**
     * Base constructor with a particular finder for signature algorithms.
     *
     * @param digestProvider a provider of digest calculators for the algorithms required in the signature and attribute calculations.
     * @param sigEncAlgFinder finder for algorithm IDs to store for the signature encryption/signature algorithm field.
     */
    public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider, CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder)
    {
        builder = new SignerInfoGeneratorBuilder(digestProvider, sigEncAlgFinder);
    }

    /**
     * If the passed in flag is true, the signer signature will be based on the data, not
     * a collection of signed attributes, and no signed attributes will be included.
     *
     * @return the builder object
     */
    public JcaSignerInfoGeneratorBuilder setDirectSignature(boolean hasNoSignedAttributes)
    {
        builder.setDirectSignature(hasNoSignedAttributes);

        return this;
    }

    public JcaSignerInfoGeneratorBuilder setContentDigest(AlgorithmIdentifier contentDigest)
    {
        builder.setContentDigest(contentDigest);

        return this;
    }

    public JcaSignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
    {
        builder.setSignedAttributeGenerator(signedGen);

        return this;
    }

    public JcaSignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
    {
        builder.setUnsignedAttributeGenerator(unsignedGen);

        return this;
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, X509CertificateHolder certHolder)
        throws OperatorCreationException
    {
        return builder.build(contentSigner, certHolder);
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, byte[] keyIdentifier)
        throws OperatorCreationException
    {
        return builder.build(contentSigner, keyIdentifier);
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, X509Certificate certificate)
        throws OperatorCreationException, CertificateEncodingException
    {
        return this.build(contentSigner, new JcaX509CertificateHolder(certificate));
    }
}
