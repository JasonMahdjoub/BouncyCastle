package com.distrimind.bouncycastle.openpgp.bc;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import com.distrimind.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import com.distrimind.bouncycastle.openpgp.PGPObjectFactory;

/**
 * {@link PGPObjectFactory} that uses the Bouncy Castle lightweight API to implement cryptographic
 * primitives.
 */
public class BcPGPObjectFactory
    extends PGPObjectFactory
{
    /**
     * Construct an object factory to read PGP objects from encoded data.
     * 
     * @param encoded the PGP encoded data.
     */
    public BcPGPObjectFactory(byte[] encoded)
    {
        this(new ByteArrayInputStream(encoded));
    }

    /**
     * Construct an object factory to read PGP objects from a stream.
     *
     * @param in the stream containing PGP encoded objects.
     */
    public BcPGPObjectFactory(InputStream in)
    {
        super(in, new BcKeyFingerprintCalculator());
    }
}
