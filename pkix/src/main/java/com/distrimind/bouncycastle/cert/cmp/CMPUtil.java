package com.distrimind.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import com.distrimind.bouncycastle.asn1.ASN1Encoding;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import com.distrimind.bouncycastle.operator.DigestCalculator;
import com.distrimind.bouncycastle.operator.DigestCalculatorProvider;
import com.distrimind.bouncycastle.operator.OperatorCreationException;

class CMPUtil
{
    static byte[] calculateCertHash(ASN1Object obj, AlgorithmIdentifier signatureAlgorithm,
        DigestCalculatorProvider digesterProvider, DigestAlgorithmIdentifierFinder digestAlgFinder)
        throws CMPException
    {
        AlgorithmIdentifier digestAlgorithm = digestAlgFinder.find(signatureAlgorithm);
        if (digestAlgorithm == null)
        {
            throw new CMPException("cannot find digest algorithm from signature algorithm");
        }

        return calculateDigest(obj, digestAlgorithm, digesterProvider);
    }

    static byte[] calculateDigest(ASN1Object obj, AlgorithmIdentifier digestAlgorithm,
        DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        DigestCalculator digestCalculator = getDigestCalculator(digestAlgorithm, digesterProvider);

        derEncodeToStream(obj, digestCalculator.getOutputStream());

        return digestCalculator.getDigest();
    }

    static void derEncodeToStream(ASN1Object obj, OutputStream stream)
    {
        try
        {
            obj.encodeTo(stream, ASN1Encoding.DER);
            stream.close();
        }
        catch (IOException e)
        {
            throw new CMPRuntimeException("unable to DER encode object: " + e.getMessage(), e);
        }
    }

    static DigestCalculator getDigestCalculator(AlgorithmIdentifier digestAlgorithm,
        DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        try
        {
            return digesterProvider.get(digestAlgorithm);
        }
        catch (OperatorCreationException e)
        {
            throw new CMPException("unable to create digester: " + e.getMessage(), e);
        }
    }
}
