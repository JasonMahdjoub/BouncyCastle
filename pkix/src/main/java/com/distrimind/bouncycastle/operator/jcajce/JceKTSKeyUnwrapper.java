package com.distrimind.bouncycastle.operator.jcajce;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import com.distrimind.bouncycastle.asn1.cms.GenericHybridParameters;
import com.distrimind.bouncycastle.asn1.cms.RsaKemParameters;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.util.DEROtherInfo;
import com.distrimind.bouncycastle.jcajce.spec.KTSParameterSpec;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.operator.AsymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.operator.OperatorException;
import com.distrimind.bouncycastle.util.Arrays;

public class JceKTSKeyUnwrapper
    extends AsymmetricKeyUnwrapper
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private Map extraMappings = new HashMap();
    private PrivateKey privKey;
    private byte[] partyUInfo;
    private byte[] partyVInfo;

    public JceKTSKeyUnwrapper(AlgorithmIdentifier algorithmIdentifier, PrivateKey privKey, byte[] partyUInfo, byte[] partyVInfo)
    {
        super(algorithmIdentifier);

        this.privKey = privKey;
        this.partyUInfo = Arrays.clone(partyUInfo);
        this.partyVInfo = Arrays.clone(partyVInfo);
    }

    public JceKTSKeyUnwrapper setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JceKTSKeyUnwrapper setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        GenericHybridParameters params = GenericHybridParameters.getInstance(this.getAlgorithmIdentifier().getParameters());
        Cipher keyCipher = helper.createAsymmetricWrapper(this.getAlgorithmIdentifier().getAlgorithm(), extraMappings);
        String symmetricWrappingAlg = helper.getWrappingAlgorithmName(params.getDem().getAlgorithm());
        RsaKemParameters kemParameters = RsaKemParameters.getInstance(params.getKem().getParameters());
        int keySizeInBits = kemParameters.getKeyLength().intValue() * 8;
        Key sKey;

        try
        {
            DEROtherInfo otherInfo = new DEROtherInfo.Builder(params.getDem(), partyUInfo, partyVInfo).build();
            KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder(symmetricWrappingAlg, keySizeInBits, otherInfo.getEncoded()).withKdfAlgorithm(kemParameters.getKeyDerivationFunction()).build();

            keyCipher.init(Cipher.UNWRAP_MODE, privKey, ktsSpec);

            sKey = keyCipher.unwrap(encryptedKey, helper.getKeyAlgorithmName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);
        }
        catch (Exception e)
        {
            throw new OperatorException("Unable to unwrap contents key: " + e.getMessage(), e);
        }

        return new JceGenericKey(encryptedKeyAlgorithm, sKey);
    }
}
