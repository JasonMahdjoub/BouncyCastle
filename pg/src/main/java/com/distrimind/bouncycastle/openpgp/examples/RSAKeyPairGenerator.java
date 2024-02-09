package com.distrimind.bouncycastle.openpgp.examples;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.distrimind.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import com.distrimind.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import com.distrimind.bouncycastle.openpgp.operator.PGPDigestCalculator;
import com.distrimind.bouncycastle.bcpg.ArmoredOutputStream;
import com.distrimind.bouncycastle.bcpg.CompressionAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.HashAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.sig.Features;
import com.distrimind.bouncycastle.bcpg.sig.KeyFlags;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPKeyPair;
import com.distrimind.bouncycastle.openpgp.PGPKeyRingGenerator;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;
import com.distrimind.bouncycastle.openpgp.PGPPublicKeyRing;
import com.distrimind.bouncycastle.openpgp.PGPSecretKeyRing;
import com.distrimind.bouncycastle.openpgp.PGPSignature;
import com.distrimind.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates an RSA key ring.
 * <p>
 * usage: RSAKeyPairGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are placed
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 */
public class RSAKeyPairGenerator
{

    private static final int SIG_HASH = HashAlgorithmTags.SHA512;
    private static final int[] HASH_PREFERENCES = new int[]{
        HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA224
    };
    private static final int[] SYM_PREFERENCES = new int[]{
        SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
    };
    private static final int[] COMP_PREFERENCES = new int[]{
        CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.UNCOMPRESSED
    };

    private static void generateAndExportKeyRing(
        OutputStream secretOut,
        OutputStream publicOut,
        String identity,
        char[] passPhrase,
        boolean armor)
        throws IOException, NoSuchProviderException, PGPException, NoSuchAlgorithmException
    {
        if (armor)
        {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, SIG_HASH).setProvider("BC");
        PBESecretKeyEncryptor secretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha1Calc).setProvider("BC")
            .build(passPhrase);

        Date now = new Date();

        kpg.initialize(3072);
        KeyPair primaryKP = kpg.generateKeyPair();
        PGPKeyPair primaryKey = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, primaryKP, now);
        PGPSignatureSubpacketGenerator primarySubpackets = new PGPSignatureSubpacketGenerator();
        primarySubpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER);
        primarySubpackets.setPreferredHashAlgorithms(false, HASH_PREFERENCES);
        primarySubpackets.setPreferredSymmetricAlgorithms(false, SYM_PREFERENCES);
        primarySubpackets.setPreferredCompressionAlgorithms(false, COMP_PREFERENCES);
        primarySubpackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        primarySubpackets.setIssuerFingerprint(false, primaryKey.getPublicKey());

        kpg.initialize(3072);
        KeyPair signingKP = kpg.generateKeyPair();
        PGPKeyPair signingKey = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, signingKP, now);
        PGPSignatureSubpacketGenerator signingKeySubpacket = new PGPSignatureSubpacketGenerator();
        signingKeySubpacket.setKeyFlags(true, KeyFlags.SIGN_DATA);
        signingKeySubpacket.setIssuerFingerprint(false, primaryKey.getPublicKey());

        kpg.initialize(3072);
        KeyPair encryptionKP = kpg.generateKeyPair();
        PGPKeyPair encryptionKey = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, encryptionKP, now);
        PGPSignatureSubpacketGenerator encryptionKeySubpackets = new PGPSignatureSubpacketGenerator();
        encryptionKeySubpackets.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        encryptionKeySubpackets.setIssuerFingerprint(false, primaryKey.getPublicKey());

        PGPKeyRingGenerator gen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primaryKey, identity,
            sha1Calc, primarySubpackets.generate(), null, contentSignerBuilder, secretKeyEncryptor);
        gen.addSubKey(signingKey, signingKeySubpacket.generate(), null, contentSignerBuilder);
        gen.addSubKey(encryptionKey, encryptionKeySubpackets.generate(), null);

        PGPSecretKeyRing secretKeys = gen.generateSecretKeyRing();
        secretKeys.encode(secretOut);

        secretOut.close();

        if (armor)
        {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        List<PGPPublicKey> publicKeyList = new ArrayList<PGPPublicKey>();
        Iterator<PGPPublicKey> it = secretKeys.getPublicKeys();
        while (it.hasNext())
        {
            publicKeyList.add(it.next());
        }

        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(publicKeyList);

        publicKeys.encode(publicOut);

        publicOut.close();
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length < 2)
        {
            System.out.println("RSAKeyPairGenerator [-a] identity passPhrase");
            System.exit(0);
        }

        if (args[0].equals("-a"))
        {
            if (args.length < 3)
            {
                System.out.println("RSAKeyPairGenerator [-a] identity passPhrase");
                System.exit(0);
            }

            FileOutputStream out1 = new FileOutputStream("secret.asc");
            FileOutputStream out2 = new FileOutputStream("pub.asc");

            generateAndExportKeyRing(out1, out2, args[1], args[2].toCharArray(), true);
        }
        else
        {
            FileOutputStream out1 = new FileOutputStream("secret.bpg");
            FileOutputStream out2 = new FileOutputStream("pub.bpg");

            generateAndExportKeyRing(out1, out2, args[0], args[1].toCharArray(), false);
        }
    }
}
