package com.distrimind.bouncycastle.cms.jcajce;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.SymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.operator.jcajce.JceAsymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.operator.jcajce.JceKTSKeyUnwrapper;
import com.distrimind.bouncycastle.operator.jcajce.JceSymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;

class DefaultJcaJceExtHelper
    extends DefaultJcaJceHelper
    implements JcaJceExtHelper
{
    public JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey)
    {
        keyEncryptionKey = CMSUtils.cleanPrivateKey(keyEncryptionKey);
        return new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
    }

    public JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo)
    {
        keyEncryptionKey = CMSUtils.cleanPrivateKey(keyEncryptionKey);
        return new JceKTSKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey, partyUInfo, partyVInfo);
    }

    public SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey)
    {
        return new JceSymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
    }
}
