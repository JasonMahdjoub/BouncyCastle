package org.bouncycastle.openssl.jcajce;

import java.security.PrivateKey;

import org.bouncycastle.bcasn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.bcutil.io.pem.PemGenerationException;

public class JcaPKCS8Generator
    extends PKCS8Generator
{
    public JcaPKCS8Generator(PrivateKey key, OutputEncryptor encryptor)
         throws PemGenerationException
    {
         super(PrivateKeyInfo.getInstance(key.getEncoded()), encryptor);
    }
}
