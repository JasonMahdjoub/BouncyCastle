package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import com.distrimind.bouncycastle.asn1.x509.Certificate;
import com.distrimind.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.util.CollectionStore;
import com.distrimind.bouncycastle.util.Store;

public class OriginatorInformation
{
    private OriginatorInfo originatorInfo;

    OriginatorInformation(OriginatorInfo originatorInfo)
    {
        this.originatorInfo = originatorInfo;
    }

    /**
     * Return the certificates stored in the underlying OriginatorInfo object.
     *
     * @return a Store of X509CertificateHolder objects.
     */
    public Store getCertificates()
    {
        ASN1Set certSet = originatorInfo.getCertificates();

        if (certSet != null)
        {
            List certList = new ArrayList(certSet.size());

            for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1Sequence)
                {
                    certList.add(new X509CertificateHolder(Certificate.getInstance(obj)));
                }
            }

            return new CollectionStore(certList);
        }

        return new CollectionStore(new ArrayList());
    }

    /**
     * Return the CRLs stored in the underlying OriginatorInfo object.
     *
     * @return a Store of X509CRLHolder objects.
     */
    public Store getCRLs()
    {
        ASN1Set crlSet = originatorInfo.getCRLs();

        if (crlSet != null)
        {
            List    crlList = new ArrayList(crlSet.size());

            for (Enumeration en = crlSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1Sequence)
                {
                    crlList.add(new X509CRLHolder(CertificateList.getInstance(obj)));
                }
            }

            return new CollectionStore(crlList);
        }

        return new CollectionStore(new ArrayList());
    }

    /**
     * Return the underlying ASN.1 object defining this SignerInformation object.
     *
     * @return a OriginatorInfo.
     */
    public OriginatorInfo toASN1Structure()
    {
        return originatorInfo;
    }
}
