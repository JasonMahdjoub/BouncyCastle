package com.distrimind.bouncycastle.asn1.cmc.test;

import java.util.Date;

import com.distrimind.bouncycastle.asn1.DERGeneralizedTime;
import com.distrimind.bouncycastle.asn1.cmc.BodyPartID;
import com.distrimind.bouncycastle.asn1.cmc.CMCFailInfo;
import com.distrimind.bouncycastle.asn1.cmc.CMCStatus;
import com.distrimind.bouncycastle.asn1.cmc.CMCStatusInfo;
import com.distrimind.bouncycastle.asn1.cmc.CMCStatusInfoBuilder;
import com.distrimind.bouncycastle.asn1.cmc.PendInfo;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.test.SimpleTest;


public class CMCStatusInfoTest
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new CMCStatusInfoTest());
    }

    public String getName()
    {
        return "CMCStatusInfoTest";
    }

    public void performTest()
        throws Exception
    {
        { // Without optional status String

             CMCStatusInfoBuilder bldr =
                 new CMCStatusInfoBuilder(CMCStatus.confirmRequired, new BodyPartID(10));

             CMCStatusInfo cmsInfo = bldr.build();

             isTrue("Has statusString", null == cmsInfo.getStatusStringUTF8());
             isEquals("Has other info", false, cmsInfo.hasOtherInfo());

             byte[] b = cmsInfo.getEncoded();
             CMCStatusInfo res = CMCStatusInfo.getInstance(b);

             // Same
             isEquals("CMCStatus with no optional part",cmsInfo, res);

             isEquals("Has other info", false, res.hasOtherInfo());

         }

        { // Without optional other info.

            CMCStatusInfoBuilder bldr =
                new CMCStatusInfoBuilder(CMCStatus.confirmRequired, new BodyPartID(10)).setStatusString("Cats");

            CMCStatusInfo cmsInfo = bldr.build();

            isEquals("Has other info", false, cmsInfo.hasOtherInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfo res = CMCStatusInfo.getInstance(b);

            // Same
            isEquals("CMCStatus with no optional part",cmsInfo, res);

            isEquals("Has other info", false, res.hasOtherInfo());

        }


        { // With optional info: PendInfo
            CMCStatusInfoBuilder bldr =
                new CMCStatusInfoBuilder(CMCStatus.confirmRequired, new BodyPartID(10))
                    .setStatusString("Cats")
                    .setOtherInfo(new PendInfo(Strings.toByteArray("fish"), new DERGeneralizedTime(new Date())));

            CMCStatusInfo cmsInfo = bldr.build();

            isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
            isEquals("Other is NOT fail info", false, cmsInfo.getOtherInfo().isFailInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfo res = CMCStatusInfo.getInstance(b);

            isEquals("With optional info: PendInfo",cmsInfo, res);

            isEquals("Must have other info", true, res.hasOtherInfo());
            isEquals("Other is NOT fail info", false, res.getOtherInfo().isFailInfo());
        }


        { // With optional info: CMCFailInfo
            CMCStatusInfoBuilder bldr =
                new CMCStatusInfoBuilder(CMCStatus.confirmRequired, new BodyPartID(10))
                    .setStatusString("Cats")
                    .setOtherInfo(CMCFailInfo.authDataFail);

            CMCStatusInfo cmsInfo = bldr.build();

            isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
            isEquals("Other is fail info", true, cmsInfo.getOtherInfo().isFailInfo());

            byte[] b = cmsInfo.getEncoded();
            CMCStatusInfo res = CMCStatusInfo.getInstance(b);

            isEquals("With optional info: CMCFailInfo",cmsInfo, res);

            isEquals("Must have other info", true, res.hasOtherInfo());
            isEquals("Other is fail info", true, res.getOtherInfo().isFailInfo());
        }

    }
}
