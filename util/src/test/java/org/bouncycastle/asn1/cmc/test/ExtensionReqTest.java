package org.bouncycastle.asn1.cmc.test;

import com.distrimind.bouncycastle.asn1.ASN1Boolean;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmc.ExtensionReq;
import com.distrimind.bouncycastle.asn1.x509.Extension;
import com.distrimind.bouncycastle.util.test.SimpleTest;


public class ExtensionReqTest
    extends SimpleTest
{
    public String getName()
    {
        return "ExtensionReqTest";
    }

    public void performTest()
        throws Exception
    {
        ExtensionReq extensionReq = new ExtensionReq(
            new Extension(
                new ASN1ObjectIdentifier("1.2.4"), ASN1Boolean.FALSE, new DEROctetString("abcdef".getBytes())
            ));
        byte[] b = extensionReq.getEncoded();

        ExtensionReq extensionReqResult = ExtensionReq.getInstance(b);

        isEquals("Extensions", extensionReq.getExtensions()[0], extensionReqResult.getExtensions()[0]);

    }

    public static void main(String[] args)
    {
        runTest(new ExtensionReqTest());
    }

}
