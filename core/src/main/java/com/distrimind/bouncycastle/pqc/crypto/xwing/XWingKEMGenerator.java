package com.distrimind.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.EncapsulatedSecretGenerator;
import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.crypto.agreement.X25519Agreement;
import com.distrimind.bouncycastle.crypto.digests.SHA3Digest;
import com.distrimind.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.X25519PublicKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import com.distrimind.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.Strings;

public class XWingKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public XWingKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        XWingPublicKeyParameters key = (XWingPublicKeyParameters)recipientKey;

        KyberKEMGenerator kybKem = new KyberKEMGenerator(sr);

        SecretWithEncapsulation kybSecWithEnc = kybKem.generateEncapsulated(key.getKyberPublicKey());
        X25519Agreement xdhAgree = new X25519Agreement();
        byte[] kybSecret = kybSecWithEnc.getSecret();
        byte[] k = new byte[kybSecret.length + xdhAgree.getAgreementSize()];

        System.arraycopy(kybSecret, 0, k, 0, kybSecret.length);

        Arrays.clear(kybSecret);

        X25519KeyPairGenerator xdhGen = new X25519KeyPairGenerator();

        xdhGen.init(new X25519KeyGenerationParameters(sr));

        AsymmetricCipherKeyPair ephXdh = xdhGen.generateKeyPair();

        xdhAgree.init(ephXdh.getPrivate());

        xdhAgree.calculateAgreement(key.getXDHPublicKey(), k, kybSecret.length);

        X25519PublicKeyParameters ephXdhPub = (X25519PublicKeyParameters)ephXdh.getPublic();

        SHA3Digest sha3 = new SHA3Digest(256);

        sha3.update(Strings.toByteArray("\\.//^\\"), 0, 6);
        sha3.update(k, 0, k.length);
        sha3.update(ephXdhPub.getEncoded(), 0, X25519PublicKeyParameters.KEY_SIZE);
        sha3.update(((X25519PublicKeyParameters)key.getXDHPublicKey()).getEncoded(), 0, X25519PublicKeyParameters.KEY_SIZE);

        byte[] kemSecret = new byte[32];

        sha3.doFinal(kemSecret, 0);

        return new SecretWithEncapsulationImpl(kemSecret, Arrays.concatenate(kybSecWithEnc.getEncapsulation(), ephXdhPub.getEncoded()));
    }
}
