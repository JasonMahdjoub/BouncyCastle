package com.distrimind.bouncycastle.asn1.test;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.asn1.ASN1IA5String;
import com.distrimind.bouncycastle.asn1.ASN1InputStream;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.asn1.DERIA5String;
import com.distrimind.bouncycastle.asn1.DERNull;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.qualified.BiometricData;
import com.distrimind.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import com.distrimind.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class BiometricDataUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "BiometricData";
    }

    private byte[] generateHash()
    {
        SecureRandom rand = new SecureRandom();
        byte[] bytes = new byte[20];
        
        rand.nextBytes(bytes);
        
        return bytes;
    }
    
    public void performTest() 
        throws Exception
    {
        TypeOfBiometricData dataType = new TypeOfBiometricData(TypeOfBiometricData.HANDWRITTEN_SIGNATURE);
        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        ASN1OctetString     dataHash = new DEROctetString(generateHash());
        BiometricData       bd = new BiometricData(dataType, hashAlgorithm, dataHash);

        checkConstruction(bd, dataType, hashAlgorithm, dataHash, null);
        
        ASN1IA5String dataUri = new DERIA5String("http://test");
        
        bd = new BiometricData(dataType, hashAlgorithm, dataHash, dataUri);
        
        checkConstruction(bd, dataType, hashAlgorithm, dataHash, dataUri);
        
        bd = BiometricData.getInstance(null);
        
        if (bd != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            BiometricData.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        BiometricData bd,
        TypeOfBiometricData dataType, 
        AlgorithmIdentifier hashAlgorithm,
        ASN1OctetString dataHash, 
        ASN1IA5String dataUri)
        throws Exception
    {
        checkValues(bd, dataType, hashAlgorithm, dataHash, dataUri);

        bd = BiometricData.getInstance(bd);

        checkValues(bd, dataType, hashAlgorithm, dataHash, dataUri);

        ASN1InputStream aIn = new ASN1InputStream(bd.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        bd = BiometricData.getInstance(seq);

        checkValues(bd, dataType, hashAlgorithm, dataHash, dataUri);
    }

    private void checkValues(
        BiometricData       bd,
        TypeOfBiometricData dataType,
        AlgorithmIdentifier algID,
        ASN1OctetString     dataHash,
        ASN1IA5String       sourceDataURI)
    {
        if (!bd.getTypeOfBiometricData().equals(dataType))
        {
            fail("types don't match.");
        }
        
        if (!bd.getHashAlgorithm().equals(algID))
        {
            fail("hash algorithms don't match.");
        }
        
        if (!bd.getBiometricDataHash().equals(dataHash))
        {
            fail("hash algorithms don't match.");
        }
        
        if (sourceDataURI != null)
        {
            if (!bd.getSourceDataUriIA5().equals(sourceDataURI))
            {
                fail("data uris don't match.");
            }
        }
        else if (bd.getSourceDataUriIA5() != null)
        {
            fail("data uri found when none expected.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new BiometricDataUnitTest());
    }
}
