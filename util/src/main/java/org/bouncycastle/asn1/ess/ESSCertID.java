package com.distrimind.bouncycastle.asn1.ess;

import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.x509.IssuerSerial;
import com.distrimind.bouncycastle.util.Arrays;

public class ESSCertID
    extends ASN1Object
{
    private ASN1OctetString certHash;

    private IssuerSerial issuerSerial;

    public static ESSCertID getInstance(Object o)
    {
        if (o instanceof ESSCertID)
        {
            return (ESSCertID)o;
        }
        else if (o != null)
        {
            return new ESSCertID(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * constructor
     */
    private ESSCertID(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
 
        if (seq.size() > 1)
        {
            issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
        }
    }

    public ESSCertID(
        byte[]          hash)
    {
        certHash = new DEROctetString(Arrays.clone(hash));
    }

    public ESSCertID(
        byte[]          hash,
        IssuerSerial    issuerSerial)
    {
        this.certHash = new DEROctetString(Arrays.clone(hash));
        this.issuerSerial = issuerSerial;
    }

    public byte[] getCertHash()
    {
        return certHash.getOctets();
    }

    public IssuerSerial getIssuerSerial()
    {
        return issuerSerial;
    }

    /**
     * <pre>
     * ESSCertID ::= SEQUENCE {
     *     certHash Hash, 
     *     issuerSerial IssuerSerial OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        
        v.add(certHash);
        
        if (issuerSerial != null)
        {
            v.add(issuerSerial);
        }

        return new DERSequence(v);
    }
}
