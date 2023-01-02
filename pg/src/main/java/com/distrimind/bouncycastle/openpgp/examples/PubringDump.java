package com.distrimind.bouncycastle.openpgp.examples;

import java.io.FileInputStream;
import java.security.Security;
import java.util.Iterator;

import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import com.distrimind.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;
import com.distrimind.bouncycastle.openpgp.PGPPublicKeyRing;
import com.distrimind.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import com.distrimind.bouncycastle.openpgp.PGPUtil;
import com.distrimind.bouncycastle.util.encoders.Hex;

/**
 * Basic class which just lists the contents of the public key file passed
 * as an argument. If the file contains more than one "key ring" they are
 * listed in the order found.
 */
public class PubringDump 
{
    public static String getAlgorithm(
        int    algId)
    {
        switch (algId)
        {
        case PublicKeyAlgorithmTags.RSA_GENERAL:
            return "RSA_GENERAL";
        case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            return "RSA_ENCRYPT";
        case PublicKeyAlgorithmTags.RSA_SIGN:
            return "RSA_SIGN";
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            return "ELGAMAL_ENCRYPT";
        case PublicKeyAlgorithmTags.DSA:
            return "DSA";
        case PublicKeyAlgorithmTags.ECDH:
            return "ECDH";
        case PublicKeyAlgorithmTags.ECDSA:
            return "ECDSA";
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            return "ELGAMAL_GENERAL";
        case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
            return "DIFFIE_HELLMAN";
        }

        return "unknown";
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        //
        // Read the public key rings
        //
        PGPPublicKeyRingCollection    pubRings = new PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(new FileInputStream(args[0])), new JcaKeyFingerprintCalculator());

        Iterator    rIt = pubRings.getKeyRings();
            
        while (rIt.hasNext())
        {
            PGPPublicKeyRing    pgpPub = (PGPPublicKeyRing)rIt.next();

            try
            {
                pgpPub.getPublicKey();
            }
            catch (Exception e)
            {
                e.printStackTrace();
                continue;
            }

            Iterator    it = pgpPub.getPublicKeys();
            boolean     first = true;
            while (it.hasNext())
            {
                PGPPublicKey    pgpKey = (PGPPublicKey)it.next();

                if (first)
                {
                    System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
                    first = false;
                }
                else
                {
                    System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                }
                System.out.println("            Algorithm: " + getAlgorithm(pgpKey.getAlgorithm()));
                System.out.println("            Fingerprint: " + new String(Hex.encode(pgpKey.getFingerprint())));
            }
        }
    }
}
