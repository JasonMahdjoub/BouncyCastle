package com.distrimind.bouncycastle.asn1.util.test;

import com.distrimind.bouncycastle.asn1.icao.test.*;
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
import com.distrimind.bouncycastle.asn1.smime.test.SMIMETest;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new BodyPartIDTest(),
        new BodyPartListTest(),
        new BodyPartPathTest(),
        new BodyPartReferenceTest(),
        new CMCCertificationRequestTest(),
        new CMCPublicationInfoTest(),
        new CMCStatusInfoTest(),
        new CMCStatusInfoV2Test(),
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
        new CscaMasterListTest(),
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
