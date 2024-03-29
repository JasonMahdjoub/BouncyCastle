package com.distrimind.bouncycastle.pqc.legacy.crypto.test;

import java.math.BigInteger;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.digests.SHA224Digest;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bouncycastle.pqc.crypto.DigestingMessageSigner;
import com.distrimind.bouncycastle.pqc.crypto.DigestingStateAwareMessageSigner;
import com.distrimind.bouncycastle.pqc.legacy.crypto.gmss.GMSSDigestProvider;
import com.distrimind.bouncycastle.pqc.legacy.crypto.gmss.GMSSKeyGenerationParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.gmss.GMSSKeyPairGenerator;
import com.distrimind.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.gmss.GMSSPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.legacy.crypto.gmss.GMSSSigner;
import com.distrimind.bouncycastle.pqc.legacy.crypto.gmss.GMSSStateAwareSigner;
import com.distrimind.bouncycastle.util.BigIntegers;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class GMSSSignerTest
    extends SimpleTest
{
    public String getName()
    {
        return "GMSS";
    }

    public void performTest()
        throws Exception
    {
        GMSSParameters params = new GMSSParameters(3,
            new int[]{15, 15, 10}, new int[]{5, 5, 4}, new int[]{3, 3, 2});

        GMSSDigestProvider digProvider = new GMSSDigestProvider()
        {
            public Digest get()
            {
                return new SHA224Digest();
            }
        };

        GMSSKeyPairGenerator gmssKeyGen = new GMSSKeyPairGenerator(digProvider);

        GMSSKeyGenerationParameters genParam = new GMSSKeyGenerationParameters(null, params);

        gmssKeyGen.init(genParam);

        AsymmetricCipherKeyPair pair = gmssKeyGen.generateKeyPair();

        GMSSPrivateKeyParameters privKey = (GMSSPrivateKeyParameters)pair.getPrivate();

        ParametersWithRandom param = new ParametersWithRandom(privKey, null);

        // TODO
        Signer gmssSigner = new DigestingMessageSigner(new GMSSSigner(digProvider), new SHA224Digest());
        gmssSigner.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        gmssSigner.update(message, 0, message.length);
        byte[] sig = gmssSigner.generateSignature();


        gmssSigner.init(false, pair.getPublic());
        gmssSigner.update(message, 0, message.length);
        if (!gmssSigner.verifySignature(sig))
        {
            fail("verification fails");
        }

        if (!((GMSSPrivateKeyParameters)pair.getPrivate()).isUsed())
        {
            fail("private key not marked as used");
        }

        stateAwareTest(privKey.nextKey(), pair.getPublic());
    }

    private void stateAwareTest(GMSSPrivateKeyParameters privKey, AsymmetricKeyParameter pub)
    {
        DigestingStateAwareMessageSigner statefulSigner = new DigestingStateAwareMessageSigner(new GMSSStateAwareSigner(new SHA224Digest()), new SHA224Digest());
        statefulSigner.init(true, new ParametersWithRandom(privKey, CryptoServicesRegistrar.getSecureRandom()));

        byte[] mes1 = Strings.toByteArray("Message One");
        statefulSigner.update(mes1, 0, mes1.length);
        byte[] sig1 = statefulSigner.generateSignature();

        isTrue(privKey.isUsed());

        byte[] mes2 = Strings.toByteArray("Message Two");
        statefulSigner.update(mes2, 0, mes2.length);
        byte[] sig2 = statefulSigner.generateSignature();

        GMSSPrivateKeyParameters recoveredKey = (GMSSPrivateKeyParameters)statefulSigner.getUpdatedPrivateKey();

        isTrue(recoveredKey.isUsed() == false);

        try
        {
            statefulSigner.generateSignature();
        }
        catch (IllegalStateException e)
        {
            isEquals("signing key no longer usable", e.getMessage());
        }

        statefulSigner.init(false, pub);
        statefulSigner.update(mes2, 0, mes2.length);
        if (!statefulSigner.verifySignature(sig2))
        {
            fail("verification two fails");
        }

        statefulSigner.update(mes1, 0, mes1.length);
        if (!statefulSigner.verifySignature(sig1))
        {
            fail("verification one fails");
        }
    }

    public static void main(
        String[] args)
    {
        runTest(new GMSSSignerTest());
    }
}
