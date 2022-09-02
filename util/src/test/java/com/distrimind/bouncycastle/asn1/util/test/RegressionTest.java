package com.distrimind.bouncycastle.asn1.util.test;

import com.distrimind.bouncycastle.asn1.cmp.test.CertifiedKeyPairTest;
import com.distrimind.bouncycastle.asn1.cmp.test.PKIFailureInfoTest;
import com.distrimind.bouncycastle.asn1.cmp.test.PollReqContentTest;
import com.distrimind.bouncycastle.asn1.cms.test.AttributeTableUnitTest;
import com.distrimind.bouncycastle.asn1.cms.test.CMSTest;
import com.distrimind.bouncycastle.asn1.esf.test.SignerLocationUnitTest;
import com.distrimind.bouncycastle.asn1.smime.test.SMIMETest;
import com.distrimind.bouncycastle.asn1.cmc.test.BodyPartIDTest;
import com.distrimind.bouncycastle.asn1.cmc.test.BodyPartListTest;
import com.distrimind.bouncycastle.asn1.cmc.test.BodyPartPathTest;
import com.distrimind.bouncycastle.asn1.cmc.test.BodyPartReferenceTest;
import com.distrimind.bouncycastle.asn1.cmc.test.CMCCertificationRequestTest;
import com.distrimind.bouncycastle.asn1.cmc.test.CMCFailInfoTest;
import com.distrimind.bouncycastle.asn1.cmc.test.CMCPublicationInfoTest;
import com.distrimind.bouncycastle.asn1.cmc.test.CMCStatusInfoTest;
import com.distrimind.bouncycastle.asn1.cmc.test.CMCStatusInfoV2Test;
import com.distrimind.bouncycastle.asn1.cmc.test.CMCStatusTest;
import com.distrimind.bouncycastle.asn1.cmc.test.CMCUnsignedDataTest;
import com.distrimind.bouncycastle.asn1.cmc.test.ControlsProcessedTest;
import com.distrimind.bouncycastle.asn1.cmc.test.DecryptedPOPTest;
import com.distrimind.bouncycastle.asn1.cmc.test.EncryptedPOPTest;
import com.distrimind.bouncycastle.asn1.cmc.test.ExtendedFailInfoTest;
import com.distrimind.bouncycastle.asn1.cmc.test.ExtensionReqTest;
import com.distrimind.bouncycastle.asn1.cmc.test.GetCRLTest;
import com.distrimind.bouncycastle.asn1.cmc.test.GetCertTest;
import com.distrimind.bouncycastle.asn1.cmc.test.IdentityProofV2Test;
import com.distrimind.bouncycastle.asn1.cmc.test.LraPopWitnessTest;
import com.distrimind.bouncycastle.asn1.cmc.test.ModCertTemplateTest;
import com.distrimind.bouncycastle.asn1.cmc.test.OtherMsgTest;
import com.distrimind.bouncycastle.asn1.cmc.test.OtherStatusInfoTest;
import com.distrimind.bouncycastle.asn1.cmc.test.PKIDataTest;
import com.distrimind.bouncycastle.asn1.cmc.test.PKIResponseTest;
import com.distrimind.bouncycastle.asn1.cmc.test.PendInfoTest;
import com.distrimind.bouncycastle.asn1.cmc.test.PopLinkWitnessV2Test;
import com.distrimind.bouncycastle.asn1.cmc.test.PublishTrustAnchorsTest;
import com.distrimind.bouncycastle.asn1.cmc.test.RevokeRequestTest;
import com.distrimind.bouncycastle.asn1.cmc.test.TaggedAttributeTest;
import com.distrimind.bouncycastle.asn1.cmc.test.TaggedCertificationRequestTest;
import com.distrimind.bouncycastle.asn1.cmc.test.TaggedContentInfoTest;
import com.distrimind.bouncycastle.asn1.cmc.test.TaggedRequestTest;
import com.distrimind.bouncycastle.asn1.crmf.test.DhSigStaticTest;
import com.distrimind.bouncycastle.asn1.crmf.test.PKIPublicationInfoTest;
import com.distrimind.bouncycastle.asn1.esf.test.CommitmentTypeIndicationUnitTest;
import com.distrimind.bouncycastle.asn1.esf.test.CommitmentTypeQualifierUnitTest;
import com.distrimind.bouncycastle.asn1.ess.test.ContentHintsUnitTest;
import com.distrimind.bouncycastle.asn1.ess.test.ESSCertIDv2UnitTest;
import com.distrimind.bouncycastle.asn1.ess.test.OtherCertIDUnitTest;
import com.distrimind.bouncycastle.asn1.ess.test.OtherSigningCertificateUnitTest;
import com.distrimind.bouncycastle.asn1.icao.test.CscaMasterListTest;
import com.distrimind.bouncycastle.asn1.icao.test.DataGroupHashUnitTest;
import com.distrimind.bouncycastle.asn1.icao.test.LDSSecurityObjectUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.AdditionalInformationSyntaxUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.AdmissionSyntaxUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.AdmissionsUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.CertHashUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.DeclarationOfMajorityUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.MonetaryLimitUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.NamingAuthorityUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.ProcurationSyntaxUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.RequestedCertificateUnitTest;
import com.distrimind.bouncycastle.asn1.isismtt.test.RestrictionUnitTest;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new BodyPartIDTest(),
        new BodyPartListTest(),
        new BodyPartPathTest(),
        new BodyPartReferenceTest(),
        new CMCCertificationRequestTest(),
        new CMCFailInfoTest(),
        new CMCPublicationInfoTest(),
        new CMCStatusInfoTest(),
        new CMCPublicationInfoTest(),
        new CMCStatusInfoTest(),
        new CMCStatusInfoV2Test(),
        new CMCStatusTest(),
        new CMCUnsignedDataTest(),
        new ControlsProcessedTest(),
        new DecryptedPOPTest(),
        new EncryptedPOPTest(),
        new ExtendedFailInfoTest(),
        new ExtensionReqTest(),
        new GetCertTest(),
        new GetCRLTest(),
        new IdentityProofV2Test(),
        new LraPopWitnessTest(),
        new ModCertTemplateTest(),
        new OtherMsgTest(),
        new OtherStatusInfoTest(),
        new PendInfoTest(),
        new PKIDataTest(),
        new PKIResponseTest(),
        new PopLinkWitnessV2Test(),
        new PublishTrustAnchorsTest(),
        new RevokeRequestTest(),
        new TaggedAttributeTest(),
        new TaggedCertificationRequestTest(),
        new TaggedContentInfoTest(),
        new TaggedRequestTest(),
        new CertifiedKeyPairTest(),
        new PKIFailureInfoTest(),
        new PollReqContentTest(),
        new AttributeTableUnitTest(),
        new CMSTest(),
        new DhSigStaticTest(),
        new PKIPublicationInfoTest(),
        new CommitmentTypeIndicationUnitTest(),
        new CommitmentTypeQualifierUnitTest(),
        new SignerLocationUnitTest(),
        new ContentHintsUnitTest(),
        new ESSCertIDv2UnitTest(),
        new OtherCertIDUnitTest(),
        new OtherSigningCertificateUnitTest(),
        //new CscaMasterListTest(),
        new DataGroupHashUnitTest(),
        new LDSSecurityObjectUnitTest(),
        new AdditionalInformationSyntaxUnitTest(),
        new AdmissionsUnitTest(),
        new AdmissionSyntaxUnitTest(),
        new CertHashUnitTest(),
        new DeclarationOfMajorityUnitTest(),
        new MonetaryLimitUnitTest(),
        new NamingAuthorityUnitTest(),
        new ProcurationSyntaxUnitTest(),
        new RequestedCertificateUnitTest(),
        new RestrictionUnitTest(),
        new SMIMETest(),
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
