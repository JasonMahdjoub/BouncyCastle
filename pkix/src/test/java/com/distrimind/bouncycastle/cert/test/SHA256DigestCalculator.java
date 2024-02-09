package com.distrimind.bouncycastle.cert.test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import com.distrimind.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA256Digest;
import com.distrimind.bouncycastle.operator.DigestCalculator;


class SHA256DigestCalculator
    implements DigestCalculator
{
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    }

    public OutputStream getOutputStream()
    {
        return bOut;
    }

    public byte[] getDigest()
    {
        byte[] bytes = bOut.toByteArray();

        bOut.reset();

        Digest sha256 = SHA256Digest.newInstance();

        sha256.update(bytes, 0, bytes.length);

        byte[] digest = new byte[sha256.getDigestSize()];

        sha256.doFinal(digest, 0);

        return digest;
    }
}
