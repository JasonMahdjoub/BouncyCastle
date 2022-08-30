package org.bouncycastle.pkcs.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.BufferedBlockCipher;
import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.ExtendedDigest;
import com.distrimind.bouncycastle.crypto.digests.SHA1Digest;
import com.distrimind.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import com.distrimind.bouncycastle.crypto.io.CipherOutputStream;
import com.distrimind.bouncycastle.crypto.paddings.PKCS7Padding;
import com.distrimind.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;

public class BcPKCS12PBEOutputEncryptorBuilder
{
    private ExtendedDigest digest;

    private BufferedBlockCipher engine;
    private ASN1ObjectIdentifier algorithm;
    private SecureRandom random;
    private int iterationCount = 1024;

    public BcPKCS12PBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm, BlockCipher engine)
    {
        this(algorithm, engine, new SHA1Digest());
    }

    public BcPKCS12PBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm, BlockCipher engine, ExtendedDigest pbeDigest)
    {
        this.algorithm = algorithm;
        this.engine = new PaddedBufferedBlockCipher(engine, new PKCS7Padding());
        this.digest = pbeDigest;
    }

    public BcPKCS12PBEOutputEncryptorBuilder setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;
        return this;
    }

    public OutputEncryptor build(final char[] password)
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        final byte[] salt = new byte[20];

        random.nextBytes(salt);

        final PKCS12PBEParams pbeParams = new PKCS12PBEParams(salt, iterationCount);

        CipherParameters params = PKCS12PBEUtils.createCipherParameters(algorithm, digest, engine.getBlockSize(), pbeParams, password);

        engine.init(true, params);

        return new OutputEncryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(algorithm, pbeParams);
            }

            public OutputStream getOutputStream(OutputStream out)
            {
                return new CipherOutputStream(out, engine);
            }

            public GenericKey getKey()
            {
                return new GenericKey(new AlgorithmIdentifier(algorithm, pbeParams), PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
            }
        };
    }
}
