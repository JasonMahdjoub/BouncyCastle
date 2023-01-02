package com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece;

import com.distrimind.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.util.DigestFactory;

class Utils
{
    static Digest getDigest(AlgorithmIdentifier digest)
    {
        if (digest.getAlgorithm().equals(OIWObjectIdentifiers.idSHA1))
        {
            return DigestFactory.createSHA1();
        }
        if (digest.getAlgorithm().equals(NISTObjectIdentifiers.id_sha224))
        {
            return DigestFactory.createSHA224();
        }
        if (digest.getAlgorithm().equals(NISTObjectIdentifiers.id_sha256))
        {
            return DigestFactory.createSHA256();
        }
        if (digest.getAlgorithm().equals(NISTObjectIdentifiers.id_sha384))
        {
            return DigestFactory.createSHA384();
        }
        if (digest.getAlgorithm().equals(NISTObjectIdentifiers.id_sha512))
        {
            return DigestFactory.createSHA512();
        }
        throw new IllegalArgumentException("unrecognised OID in digest algorithm identifier: " + digest.getAlgorithm());
    }
}
