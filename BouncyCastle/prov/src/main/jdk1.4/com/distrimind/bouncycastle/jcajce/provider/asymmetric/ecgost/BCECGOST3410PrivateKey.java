package com.distrimind.bouncycastle.jcajce.provider.asymmetric.ecgost;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.asn1.DERBitString;
import com.distrimind.bouncycastle.asn1.DERNull;
import com.distrimind.bouncycastle.asn1.DEROutputStream;
import com.distrimind.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.asn1.x9.X962Parameters;
import com.distrimind.bouncycastle.asn1.x9.X9ECParameters;
import com.distrimind.bouncycastle.asn1.x9.X9ECPoint;
import com.distrimind.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import com.distrimind.bouncycastle.crypto.params.ECDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import com.distrimind.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import com.distrimind.bouncycastle.jce.interfaces.ECPointEncoder;
import com.distrimind.bouncycastle.jce.interfaces.ECPrivateKey;
import com.distrimind.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import com.distrimind.bouncycastle.jce.spec.ECParameterSpec;
import com.distrimind.bouncycastle.jce.spec.ECPrivateKeySpec;
import com.distrimind.bouncycastle.math.ec.ECCurve;
import com.distrimind.bouncycastle.math.ec.ECPoint;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

public class BCECGOST3410PrivateKey
    implements ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
{
    private String          algorithm = "ECGOST3410";
    private boolean         withCompression;

    private transient BigInteger      d;
    private transient ECParameterSpec ecSpec;
    private transient DERBitString publicKey;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected BCECGOST3410PrivateKey()
    {
    }

    BCECGOST3410PrivateKey(
        ECPrivateKey    key)
    {
        this.d = key.getD();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParameters();
    }

    public BCECGOST3410PrivateKey(
        ECPrivateKeySpec    spec)
    {
        this.d = spec.getD();
        this.ecSpec = spec.getParams();
    }

    public BCECGOST3410PrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params,
        BCECGOST3410PublicKey   pubKey,
        ECParameterSpec         spec)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            this.ecSpec = new ECParameterSpec(
                            dp.getCurve(),
                            dp.getG(),
                            dp.getN(),
                            dp.getH(),
                            dp.getSeed());
        }
        else
        {
            this.ecSpec = spec;
        }

        publicKey = getPublicKeyDetails(pubKey);
    }

    public BCECGOST3410PrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.ecSpec = null;
    }

    public BCECGOST3410PrivateKey(
        String             algorithm,
        BCECGOST3410PrivateKey    key)
    {
        this.algorithm = algorithm;
        this.d = key.d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.publicKey = key.publicKey;
        this.attrCarrier = key.attrCarrier;
    }

    BCECGOST3410PrivateKey(
        PrivateKeyInfo      info)
        throws IOException
    {
        populateFromPrivKeyInfo(info);
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info)
        throws IOException
    {
        X962Parameters      params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();
            ECDomainParameters   ecP = ECGOST3410NamedCurves.getByOID(oid);

            ecSpec = new ECNamedCurveParameterSpec(
                                        ECUtil.getCurveName(oid),
                                        ecP.getCurve(),
                                        ecP.getG(),
                                        ecP.getN(),
                                        ecP.getH(),
                                        ecP.getSeed());
        }
        else if (params.isImplicitlyCA())
        {
            ecSpec = null;
        }
        else
        {
            X9ECParameters          ecP = X9ECParameters.getInstance(params.getParameters());
            ecSpec = new ECParameterSpec(ecP.getCurve(),
                                            ecP.getG(),
                                            ecP.getN(),
                                            ecP.getH(),
                                            ecP.getSeed());
        }

        if (info.parsePrivateKey() instanceof ASN1Integer)
        {
            ASN1Integer          derD = ASN1Integer.getInstance(info.parsePrivateKey());

            this.d = derD.getValue();
        }
        else
        {
            ECPrivateKeyStructure   ec = new ECPrivateKeyStructure(ASN1Sequence.getInstance(info.parsePrivateKey()));

            this.d = ec.getKey();
            this.publicKey = ec.getPublicKey();
        }
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        X962Parameters          params = null;

        if (ecSpec instanceof ECNamedCurveParameterSpec)
        {
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveParameterSpec)ecSpec).getName());
            
            params = new X962Parameters(curveOid);
        }
        else if (ecSpec == null)
        {
            params = new X962Parameters(DERNull.INSTANCE);
        }
        else
        {
            ECParameterSpec p = (ECParameterSpec)ecSpec;

            ECPoint pG = p.getG().normalize();
            ECPoint g = pG.getCurve().createPoint(pG.getAffineXCoord().toBigInteger(), pG.getAffineYCoord().toBigInteger());

            X9ECParameters ecP = new X9ECParameters(
                  p.getCurve(),
                  new X9ECPoint(g, withCompression),
                  p.getN(),
                  p.getH(),
                  p.getSeed());

            params = new X962Parameters(ecP);
        }

        PrivateKeyInfo        info;
        ECPrivateKeyStructure keyStructure;

        if (publicKey != null)
        {
            keyStructure = new ECPrivateKeyStructure(this.getD(), publicKey, params);
        }
        else
        {
            keyStructure = new ECPrivateKeyStructure(this.getD(), params);
        }

        try
        {
            if (algorithm.equals("ECGOST3410"))
            {
                info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params), keyStructure);
            }
            else
            {
                info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);
            }

            return KeyUtil.getEncodedPrivateKeyInfo(info);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public ECParameterSpec getParams()
    {
        return (ECParameterSpec)ecSpec;
    }

    public ECParameterSpec getParameters()
    {
        return (ECParameterSpec)ecSpec;
    }
    
    public BigInteger getD()
    {
        return d;
    }

    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable        attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }
    
    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return ecSpec;
        }

        return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public String toString()
    {
        return ECUtil.privateKeyToString(algorithm, d, engineGetSpec());
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof BCECGOST3410PrivateKey))
        {
            return false;
        }

        BCECGOST3410PrivateKey other = (BCECGOST3410PrivateKey)o;

        return getD().equals(other.getD()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    private DERBitString getPublicKeyDetails(BCECGOST3410PublicKey   pub)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        }
        catch (IOException e)
        {   // should never happen
            return null;
        }
    }


    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
