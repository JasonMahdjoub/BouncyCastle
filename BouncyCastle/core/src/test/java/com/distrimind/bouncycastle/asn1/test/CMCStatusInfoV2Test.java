package com.distrimind.bouncycastle.asn1.test;

import java.util.Date;

import com.distrimind.bouncycastle.asn1.DERGeneralizedTime;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.cmc.BodyPartID;
import com.distrimind.bouncycastle.asn1.cmc.CMCFailInfo;
import com.distrimind.bouncycastle.asn1.cmc.CMCStatus;
import com.distrimind.bouncycastle.asn1.cmc.CMCStatusInfoV2;
import com.distrimind.bouncycastle.asn1.cmc.CMCStatusInfoV2Builder;
import com.distrimind.bouncycastle.asn1.cmc.ExtendedFailInfo;
import com.distrimind.bouncycastle.asn1.cmc.PendInfo;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.test.SimpleTest;


public class CMCStatusInfoV2Test
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new CMCStatusInfoV2Test());
    }

    public String getName()
    {
        return "CMCStatusInfoV2Test";
    }

    public void performTest()
        throws Exception
    {
        { // Without optional status String

            CMCStatusInfoV2Builder bldr =
                new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10));

            CMCStatusInfoV2 cmsInfo = bldr.build();

            isTrue("Has statusString", null == cmsInfo.getStatusString());
            isEquals("Has other info", false, cmsInfo.hasOtherInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

            // Same
            isEquals("CMCStatus with no optional part", cmsInfo, res);

            isEquals("Has other info", false, res.hasOtherInfo());

        }

        { // Without optional other info.

            CMCStatusInfoV2Builder bldr =
                new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10)).setStatusString("Cats");

            CMCStatusInfoV2 cmsInfo = bldr.build();

            isEquals("Has other info", false, cmsInfo.hasOtherInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

            // Same
            isEquals("CMCStatus with no optional part", cmsInfo, res);

            isEquals("Has other info", false, res.hasOtherInfo());

        }


        { // With optional info: PendInfo
            CMCStatusInfoV2Builder bldr =
                new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10))
                    .setStatusString("Cats")
                    .setOtherInfo(new PendInfo(Strings.toByteArray("fish"), new DERGeneralizedTime(new Date())));

            CMCStatusInfoV2 cmsInfo = bldr.build();

            isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
            isEquals("Other is NOT fail info", false, cmsInfo.getOtherStatusInfo().isFailInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

            isEquals("With optional info: PendInfo", cmsInfo, res);

            isEquals("Must have other info", true, res.hasOtherInfo());
            isEquals("Other is NOT fail info", false, res.getOtherStatusInfo().isFailInfo());
        }


        { // With optional info: CMCFailInfo
            CMCStatusInfoV2Builder bldr =
                new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10))
                    .setStatusString("Cats")
                    .setOtherInfo(CMCFailInfo.authDataFail);

            CMCStatusInfoV2 cmsInfo = bldr.build();

            isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
            isEquals("Other is fail info", true, cmsInfo.getOtherStatusInfo().isFailInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

            isEquals("With optional info: CMCFailInfo", cmsInfo, res);

            isEquals("Must have other info", true, res.hasOtherInfo());
            isEquals("Other is fail info", true, res.getOtherStatusInfo().isFailInfo());
        }


        { // With optional info: ExtendedFailInfo
            CMCStatusInfoV2Builder bldr =
                new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10))
                    .setStatusString("Cats")
                    .setOtherInfo(new ExtendedFailInfo(PKCSObjectIdentifiers.bagtypes, new DEROctetString("fish".getBytes())));

            CMCStatusInfoV2 cmsInfo = bldr.build();

            isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
            isEquals("Other is extended fail info", true, cmsInfo.getOtherStatusInfo().isExtendedFailInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

            isEquals("With optional info: ExtendedFailInfo", cmsInfo, res);

            isEquals("Must have other info", true, res.hasOtherInfo());
            isEquals("Other is extended fail info", true, res.getOtherStatusInfo().isExtendedFailInfo());
        }


    }
}
