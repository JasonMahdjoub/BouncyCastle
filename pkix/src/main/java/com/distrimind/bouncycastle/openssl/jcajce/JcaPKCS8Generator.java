package com.distrimind.bouncycastle.openssl.jcajce;

import java.security.PrivateKey;

import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.operator.OutputEncryptor;
import com.distrimind.bouncycastle.openssl.PKCS8Generator;
import com.distrimind.bouncycastle.util.io.pem.PemGenerationException;

public class JcaPKCS8Generator
    extends PKCS8Generator
{
    public JcaPKCS8Generator(PrivateKey key, OutputEncryptor encryptor)
         throws PemGenerationException
    {
         super(PrivateKeyInfo.getInstance(key.getEncoded()), encryptor);
    }
}
