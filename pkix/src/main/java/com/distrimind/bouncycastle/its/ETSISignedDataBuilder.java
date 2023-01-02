package com.distrimind.bouncycastle.its;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import com.distrimind.bouncycastle.its.operator.ECDSAEncoder;
import com.distrimind.bouncycastle.its.operator.ITSContentSigner;
import com.distrimind.bouncycastle.oer.Element;
import com.distrimind.bouncycastle.oer.OEREncoder;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Certificate;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.HashedData;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.HeaderInfo;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Data;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Opaque;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.SequenceOfCertificate;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.SignedData;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.SignedDataPayload;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.SignerIdentifier;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.ToBeSignedData;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.Psid;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.Time64;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;
import com.distrimind.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;

public class ETSISignedDataBuilder
{
    private static final Element def = IEEE1609dot2.ToBeSignedData.build();

    private final HeaderInfo headerInfo;

    private Ieee1609Dot2Data data;
    private HashedData extDataHash;

    private ETSISignedDataBuilder(Psid psid)
    {
        this(HeaderInfo.builder().setPsid(psid).setGenerationTime(Time64.now()).createHeaderInfo());
    }

    private ETSISignedDataBuilder(HeaderInfo headerInfo)
    {
        this.headerInfo = headerInfo;
    }

    public static ETSISignedDataBuilder builder(Psid psid)
    {
        return new ETSISignedDataBuilder(psid);
    }

    public static ETSISignedDataBuilder builder(HeaderInfo headerInfo)
    {
        return new ETSISignedDataBuilder(headerInfo);
    }

    public ETSISignedDataBuilder setData(Ieee1609Dot2Content data)
    {
        this.data = Ieee1609Dot2Data.builder()
            .setProtocolVersion(new UINT8(3))
            .setContent(data).createIeee1609Dot2Data();
        return this;
    }

    public ETSISignedDataBuilder setUnsecuredData(byte[] data)
    {
        this.data = Ieee1609Dot2Data.builder()
            .setProtocolVersion(new UINT8(3))
            .setContent(Ieee1609Dot2Content
                .unsecuredData( new Opaque(data))).createEtsiTs103097Data();
        return this;
    }

    public ETSISignedDataBuilder setExtDataHash(HashedData extDataHash)
    {
        this.extDataHash = extDataHash;
        return this;
    }

    private ToBeSignedData getToBeSignedData()
    {
        SignedDataPayload signedDataPayload = new SignedDataPayload(data, extDataHash);

        return ToBeSignedData.builder()
            .setPayload(signedDataPayload)
            .setHeaderInfo(headerInfo)
            .createToBeSignedData();
    }


    /**
     * Self signed
     *
     * @param signer
     * @return
     */
    public ETSISignedData build(ITSContentSigner signer)
    {
        ToBeSignedData toBeSignedData = getToBeSignedData();
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        Signature signature = ECDSAEncoder.toITS(signer.getCurveID(), signer.getSignature());

        return new ETSISignedData(SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.self())
            .setSignature(signature).createSignedData());
    }

    /**
     * Ceritificate
     *
     * @param signer
     * @param certificateList
     * @return
     */
    public ETSISignedData build(ITSContentSigner signer, List<ITSCertificate> certificateList)
    {
        ToBeSignedData toBeSignedData = getToBeSignedData();
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        List<Certificate> certificates = new ArrayList<Certificate>();
        for (ITSCertificate certificate : certificateList)
        {
            certificates.add(Certificate.getInstance(certificate.toASN1Structure()));
        }

        Signature signature = ECDSAEncoder.toITS(signer.getCurveID(), signer.getSignature());

        return new ETSISignedData(SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.certificate(new SequenceOfCertificate(certificates)))
            .setSignature(signature).createSignedData());
    }

    /**
     * Hash id
     *
     * @param signer
     * @param identifier
     * @return
     */
    public ETSISignedData build(ITSContentSigner signer, HashedId8 identifier)
    {

        ToBeSignedData toBeSignedData = getToBeSignedData();
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        Signature signature = ECDSAEncoder.toITS(signer.getCurveID(), signer.getSignature());

        return new ETSISignedData(SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.digest(identifier))
            .setSignature(signature).createSignedData());
    }

    private static void write(OutputStream os, byte[] data)
    {
        try
        {
            os.write(data);
            os.flush();
            os.close();
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }
}
