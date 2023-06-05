package com.distrimind.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.qtesla.QTESLAPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.sike.SIKEPrivateKeyParameters;
import com.distrimind.bouncycastle.util.Pack;
import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1Set;
import com.distrimind.bouncycastle.asn1.DERBitString;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.pqc.asn1.CMCEPrivateKey;
import com.distrimind.bouncycastle.pqc.asn1.CMCEPublicKey;
import com.distrimind.bouncycastle.pqc.asn1.FalconPrivateKey;
import com.distrimind.bouncycastle.pqc.asn1.FalconPublicKey;
import com.distrimind.bouncycastle.pqc.asn1.KyberPrivateKey;
import com.distrimind.bouncycastle.pqc.asn1.KyberPublicKey;
import com.distrimind.bouncycastle.pqc.asn1.McElieceCCA2PrivateKey;
import com.distrimind.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import com.distrimind.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import com.distrimind.bouncycastle.pqc.asn1.SPHINCSPLUSPrivateKey;
import com.distrimind.bouncycastle.pqc.asn1.SPHINCSPLUSPublicKey;
import com.distrimind.bouncycastle.pqc.asn1.XMSSKeyParams;
import com.distrimind.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import com.distrimind.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import com.distrimind.bouncycastle.pqc.asn1.XMSSPrivateKey;
import com.distrimind.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.lms.Composer;
import com.distrimind.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.xmss.BDS;
import com.distrimind.bouncycastle.pqc.crypto.xmss.BDSStateMap;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * Factory to create ASN.1 private key info objects from lightweight private keys.
 */
public class PrivateKeyInfoFactory
{
    private PrivateKeyInfoFactory()
    {

    }

    /**
     * Create a PrivateKeyInfo representation of a private key.
     *
     * @param privateKey the key to be encoded into the info object.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey) throws IOException
    {
        return createPrivateKeyInfo(privateKey, null);
    }

    /**
     * Create a PrivateKeyInfo representation of a private key with attributes.
     *
     * @param privateKey the key to be encoded into the info object.
     * @param attributes the set of attributes to be included.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException
    {
        if (privateKey instanceof QTESLAPrivateKeyParameters)
        {
            QTESLAPrivateKeyParameters keyParams = (QTESLAPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = Utils.qTeslaLookupAlgID(keyParams.getSecurityCategory());

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(keyParams.getSecret()), attributes);
        }
        else if (privateKey instanceof SPHINCSPrivateKeyParameters)
        {
            SPHINCSPrivateKeyParameters params = (SPHINCSPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                                    new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getKeyData()));
        }
        else if (privateKey instanceof NHPrivateKeyParameters)
        {
            NHPrivateKeyParameters params = (NHPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);

            short[] privateKeyData = params.getSecData();

            byte[] octets = new byte[privateKeyData.length * 2];
            for (int i = 0; i != privateKeyData.length; i++)
            {
                Pack.shortToLittleEndian(privateKeyData[i], octets, i * 2);
            }

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(octets));
        }
        else if (privateKey instanceof LMSPrivateKeyParameters)
        {
            LMSPrivateKeyParameters params = (LMSPrivateKeyParameters)privateKey;

            byte[] encoding = Composer.compose().u32str(1).bytes(params).build();
            byte[] pubEncoding = Composer.compose().u32str(1).bytes(params.getPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
        else if (privateKey instanceof HSSPrivateKeyParameters)
        {
            HSSPrivateKeyParameters params = (HSSPrivateKeyParameters)privateKey;

            byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params).build();
            byte[] pubEncoding = Composer.compose().u32str(params.getL()).bytes(params.getPublicKey().getLMSPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
        else if (privateKey instanceof SPHINCSPlusPrivateKeyParameters)
        {
            SPHINCSPlusPrivateKeyParameters params = (SPHINCSPlusPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters()));
            SPHINCSPLUSPublicKey spPub = new SPHINCSPLUSPublicKey(params.getPublicSeed(), params.getRoot());
            SPHINCSPLUSPrivateKey spPriv = new SPHINCSPLUSPrivateKey(0, params.getSeed(), params.getPrf(), spPub);

            return new PrivateKeyInfo(algorithmIdentifier, spPriv, attributes);
        }
        else if (privateKey instanceof PicnicPrivateKeyParameters)
        {

            PicnicPrivateKeyParameters params = (PicnicPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.picnicOidLookup(params.getParameters()));
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof CMCEPrivateKeyParameters)
        {
            CMCEPrivateKeyParameters params = (CMCEPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();
            //todo either make CMCEPrivateKey split the parameters from the private key or
            // (current) Make CMCEPrivateKey take parts of the private key splitted in the params

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mcElieceOidLookup(params.getParameters()));

            CMCEPublicKey cmcePub = new CMCEPublicKey(params.reconstructPublicKey());
            CMCEPrivateKey cmcePriv = new CMCEPrivateKey(0, params.getDelta(), params.getC(), params.getG(), params.getAlpha(), params.getS(), cmcePub);
            return new PrivateKeyInfo(algorithmIdentifier, cmcePriv, attributes);
        }
        else if (privateKey instanceof XMSSPrivateKeyParameters)
        {
            XMSSPrivateKeyParameters keyParams = (XMSSPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                new XMSSKeyParams(keyParams.getParameters().getHeight(),
                    Utils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, xmssCreateKeyStructure(keyParams), attributes);
        }
        else if (privateKey instanceof XMSSMTPrivateKeyParameters)
        {
            XMSSMTPrivateKeyParameters keyParams = (XMSSMTPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
                new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(),
                    Utils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, xmssmtCreateKeyStructure(keyParams), attributes);
        }
        else if (privateKey instanceof McElieceCCA2PrivateKeyParameters)
        {
            McElieceCCA2PrivateKeyParameters priv = (McElieceCCA2PrivateKeyParameters)privateKey;
            McElieceCCA2PrivateKey mcEliecePriv = new McElieceCCA2PrivateKey(priv.getN(), priv.getK(), priv.getField(), priv.getGoppaPoly(), priv.getP(), Utils.getAlgorithmIdentifier(priv.getDigest()));
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2);

            return new PrivateKeyInfo(algorithmIdentifier, mcEliecePriv);
        }
        else if (privateKey instanceof FrodoPrivateKeyParameters)
        {
            FrodoPrivateKeyParameters params = (FrodoPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.frodoOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof SABERPrivateKeyParameters)
        {
            SABERPrivateKeyParameters params = (SABERPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.saberOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof SIKEPrivateKeyParameters)
        {
            SIKEPrivateKeyParameters params = (SIKEPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sikeOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof NTRUPrivateKeyParameters)
        {
            NTRUPrivateKeyParameters params = (NTRUPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.ntruOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof FalconPrivateKeyParameters)
        {
            FalconPrivateKeyParameters params = (FalconPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.falconOidLookup(params.getParameters()));

            FalconPublicKey falconPub = new FalconPublicKey(params.getPublicKey());
            FalconPrivateKey falconPriv = new FalconPrivateKey(0, params.getSpolyf(), params.getG(), params.getSpolyF(), falconPub);

            return new PrivateKeyInfo(algorithmIdentifier, falconPriv, attributes);
        }
        else if (privateKey instanceof KyberPrivateKeyParameters)
        {
            KyberPrivateKeyParameters params = (KyberPrivateKeyParameters)privateKey;
            
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.kyberOidLookup(params.getParameters()));

            KyberPublicKey kyberPub = new KyberPublicKey(params.getT(), params.getRho());
            KyberPrivateKey kyberPriv = new KyberPrivateKey(0, params.getS(), params.getHPK(), params.getNonce(), kyberPub);

            return new PrivateKeyInfo(algorithmIdentifier, kyberPriv, attributes);
        }
        else if (privateKey instanceof NTRULPRimePrivateKeyParameters)
        {
            NTRULPRimePrivateKeyParameters params = (NTRULPRimePrivateKeyParameters)privateKey;

            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new DEROctetString(params.getEnca()));
            v.add(new DEROctetString(params.getPk()));
            v.add(new DEROctetString(params.getRho()));
            v.add(new DEROctetString(params.getHash()));

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.ntrulprimeOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DERSequence(v), attributes);
        }
        else if (privateKey instanceof SNTRUPrimePrivateKeyParameters)
        {
            SNTRUPrimePrivateKeyParameters params = (SNTRUPrimePrivateKeyParameters)privateKey;

            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new DEROctetString(params.getF()));
            v.add(new DEROctetString(params.getGinv()));
            v.add(new DEROctetString(params.getPk()));
            v.add(new DEROctetString(params.getRho()));
            v.add(new DEROctetString(params.getHash()));

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sntruprimeOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DERSequence(v), attributes);
        }
        else if (privateKey instanceof DilithiumPrivateKeyParameters)
        {
            DilithiumPrivateKeyParameters params = (DilithiumPrivateKeyParameters)privateKey;

            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new ASN1Integer(0));
            v.add(new DERBitString(params.getRho()));
            v.add(new DERBitString(params.getK()));
            v.add(new DERBitString(params.getTr()));
            v.add(new DERBitString(params.getS1()));
            v.add(new DERBitString(params.getS2()));
            v.add(new DERBitString(params.getT0()));

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.dilithiumOidLookup(params.getParameters()));

            ASN1EncodableVector vPub = new ASN1EncodableVector();
            vPub.add(new DEROctetString(params.getRho()));
            vPub.add(new DEROctetString(params.getT1()));

            return new PrivateKeyInfo(algorithmIdentifier, new DERSequence(v), attributes, new DERSequence(vPub).getEncoded());
        }
        else if (privateKey instanceof BIKEPrivateKeyParameters)
        {
            BIKEPrivateKeyParameters params = (BIKEPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.bikeOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof HQCPrivateKeyParameters)
        {
            HQCPrivateKeyParameters params = (HQCPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.hqcOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof RainbowPrivateKeyParameters)
        {
            RainbowPrivateKeyParameters params = (RainbowPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.rainbowOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }

    private static XMSSPrivateKey xmssCreateKeyStructure(XMSSPrivateKeyParameters keyParams)
        throws IOException
    {
        byte[] keyData = keyParams.getEncoded();

        int n = keyParams.getParameters().getTreeDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int indexSize = 4;
        int secretKeySize = n;
        int secretKeyPRFSize = n;
        int publicSeedSize = n;
        int rootSize = n;

        int position = 0;
        int index = (int) XMSSUtil.bytesToXBigEndian(keyData, position, indexSize);
        if (!XMSSUtil.isIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeySize);
        position += secretKeySize;
        byte[] secretKeyPRF = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeyPRFSize);
        position += secretKeyPRFSize;
        byte[] publicSeed = XMSSUtil.extractBytesAtOffset(keyData, position, publicSeedSize);
        position += publicSeedSize;
        byte[] root = XMSSUtil.extractBytesAtOffset(keyData, position, rootSize);
        position += rootSize;
               /* import BDS state */
        byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(keyData, position, keyData.length - position);
        BDS bds = null;
        try
        {
            bds = (BDS)XMSSUtil.deserialize(bdsStateBinary, BDS.class);
        }
        catch (ClassNotFoundException e)
        {
            throw new IOException("cannot parse BDS: " + e.getMessage());
        }

        if ((bds.getMaxIndex() != (1 << totalHeight) - 1))
        {
            return new XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary, bds.getMaxIndex());
        }
        else
        {
            return new XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
        }
    }

    private static XMSSMTPrivateKey xmssmtCreateKeyStructure(XMSSMTPrivateKeyParameters keyParams)
        throws IOException
    {
        byte[] keyData = keyParams.getEncoded();

        int n = keyParams.getParameters().getTreeDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int indexSize = (totalHeight + 7) / 8;
        int secretKeySize = n;
        int secretKeyPRFSize = n;
        int publicSeedSize = n;
        int rootSize = n;

        int position = 0;
        int index = (int)XMSSUtil.bytesToXBigEndian(keyData, position, indexSize);
        if (!XMSSUtil.isIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeySize);
        position += secretKeySize;
        byte[] secretKeyPRF = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeyPRFSize);
        position += secretKeyPRFSize;
        byte[] publicSeed = XMSSUtil.extractBytesAtOffset(keyData, position, publicSeedSize);
        position += publicSeedSize;
        byte[] root = XMSSUtil.extractBytesAtOffset(keyData, position, rootSize);
        position += rootSize;
               /* import BDS state */
        byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(keyData, position, keyData.length - position);
        BDSStateMap bds = null;
        try
        {
            bds = (BDSStateMap)XMSSUtil.deserialize(bdsStateBinary, BDSStateMap.class);
        }
        catch (ClassNotFoundException e)
        {
            throw new IOException("cannot parse BDSStateMap: " + e.getMessage());
        }

        if ((bds.getMaxIndex() != (1L << totalHeight) - 1))
        {
            return new XMSSMTPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary, bds.getMaxIndex());
        }
        else
        {
            return new XMSSMTPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
        }
    }
}