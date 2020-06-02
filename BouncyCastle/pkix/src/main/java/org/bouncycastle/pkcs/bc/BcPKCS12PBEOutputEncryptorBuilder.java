package org.bouncycastle.pkcs.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.bcasn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcasn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;
import org.bouncycastle.bccrypto.BlockCipher;
import org.bouncycastle.bccrypto.BufferedBlockCipher;
import org.bouncycastle.bccrypto.CipherParameters;
import org.bouncycastle.bccrypto.ExtendedDigest;
import org.bouncycastle.bccrypto.digests.SHA1Digest;
import org.bouncycastle.bccrypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.bccrypto.io.CipherOutputStream;
import org.bouncycastle.bccrypto.paddings.PKCS7Padding;
import org.bouncycastle.bccrypto.paddings.PaddedBufferedBlockCipher;
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
