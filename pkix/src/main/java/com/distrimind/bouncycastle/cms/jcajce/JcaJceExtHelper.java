package com.distrimind.bouncycastle.cms.jcajce;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.jcajce.JceAsymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.operator.jcajce.JceKTSKeyUnwrapper;
import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;
import com.distrimind.bouncycastle.operator.AsymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.operator.SymmetricKeyUnwrapper;

interface JcaJceExtHelper
    extends JcaJceHelper
{
    JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey);

    JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo);

    SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey);

    AsymmetricKeyUnwrapper createKEMUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey);
}
