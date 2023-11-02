package com.distrimind.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.DigestCalculator;
import com.distrimind.bouncycastle.operator.DigestCalculatorProvider;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.CertificateBase;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.CertificateType;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.VerificationKeyIndicator;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import com.distrimind.bouncycastle.util.Arrays;

public class ITSImplicitCertificateBuilder
    extends ITSCertificateBuilder
{
    private final IssuerIdentifier issuerIdentifier;

    public ITSImplicitCertificateBuilder(ITSCertificate issuer, DigestCalculatorProvider digestCalculatorProvider, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, tbsCertificate);
        // TODO is this always true?
        AlgorithmIdentifier digestAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        ASN1ObjectIdentifier digestAlg = digestAlgId.getAlgorithm();
        DigestCalculator calculator;
        try
        {
            calculator = digestCalculatorProvider.get(digestAlgId);
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }

        try
        {
            OutputStream os = calculator.getOutputStream();
            os.write(issuer.getEncoded());
            os.close();
        }
        catch (IOException ioex)
        {
            throw new IllegalStateException(ioex.getMessage(), ioex);
        }

        byte[] parentDigest = calculator.getDigest();


        HashedId8 hashedID = new HashedId8(Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length));


        if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
        {
            issuerIdentifier = IssuerIdentifier.sha256AndDigest(hashedID);
        }
        else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
        {
            issuerIdentifier = IssuerIdentifier.sha384AndDigest(hashedID);
        }
        else
        {
            throw new IllegalStateException("unknown digest");
        }

    }

    public ITSCertificate build(CertificateId certificateId, BigInteger x, BigInteger y)
    {
        return build(certificateId, x, y, null);
    }

    public ITSCertificate build(CertificateId certificateId, BigInteger x, BigInteger y, PublicEncryptionKey publicEncryptionKey)
    {
        EccP256CurvePoint reconstructionValue = EccP256CurvePoint.uncompressedP256(x, y);

        ToBeSignedCertificate.Builder tbsBldr = new ToBeSignedCertificate.Builder(tbsCertificateBuilder);

        tbsBldr.setId(certificateId);

        if (publicEncryptionKey != null)
        {
            tbsBldr.setEncryptionKey(publicEncryptionKey);
        }

        tbsBldr.setVerifyKeyIndicator(VerificationKeyIndicator.reconstructionValue(reconstructionValue));


        CertificateBase.Builder baseBldr = new CertificateBase.Builder();

        baseBldr.setVersion(version);
        baseBldr.setType(CertificateType.implicit);

        baseBldr.setIssuer(issuerIdentifier);

        baseBldr.setToBeSigned(tbsBldr.createToBeSignedCertificate());

        return new ITSCertificate(baseBldr.createCertificateBase());
    }
}
