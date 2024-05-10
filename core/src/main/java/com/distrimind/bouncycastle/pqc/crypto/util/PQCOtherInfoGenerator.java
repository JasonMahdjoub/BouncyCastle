package com.distrimind.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.EncapsulatedSecretExtractor;
import com.distrimind.bouncycastle.crypto.EncapsulatedSecretGenerator;
import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.util.DEROtherInfo;
import com.distrimind.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import com.distrimind.bouncycastle.pqc.crypto.ExchangePair;
import com.distrimind.bouncycastle.pqc.crypto.KEMParameters;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHAgreement;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHExchangePairGenerator;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import com.distrimind.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import com.distrimind.bouncycastle.pqc.crypto.ntru.NTRUKEMExtractor;
import com.distrimind.bouncycastle.pqc.crypto.ntru.NTRUKEMGenerator;
import com.distrimind.bouncycastle.pqc.crypto.ntru.NTRUKeyGenerationParameters;
import com.distrimind.bouncycastle.pqc.crypto.ntru.NTRUKeyPairGenerator;
import com.distrimind.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import com.distrimind.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;

/**
 * OtherInfo Generator for which can be used for populating the SuppPrivInfo field used to provide shared
 * secret data used with NIST SP 800-56A agreement algorithms.
 */
public class PQCOtherInfoGenerator
{
    protected final DEROtherInfo.Builder otherInfoBuilder;
    protected final SecureRandom random;

    protected boolean used = false;

    /**
     * Create a basic builder with just the compulsory fields.
     *
     * @param algorithmID the algorithm associated with this invocation of the KDF.
     * @param partyUInfo  sender party info.
     * @param partyVInfo  receiver party info.
     * @param random a source of randomness.
     */
    public PQCOtherInfoGenerator(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
    {
        this.otherInfoBuilder = new DEROtherInfo.Builder(algorithmID, partyUInfo, partyVInfo);
        this.random = random;
    }

    /**
     * Party U (initiator) generation.
     */
    public static class PartyU
        extends PQCOtherInfoGenerator
    {
        private AsymmetricCipherKeyPair aKp;
        private EncapsulatedSecretExtractor encSE;

        /**
         * Create a basic builder with just the compulsory fields for the initiator.
         *
         * @param kemParams the key type parameters for populating the private info field.
         * @param algorithmID the algorithm associated with this invocation of the KDF.
         * @param partyUInfo  sender party info.
         * @param partyVInfo  receiver party info.
         * @param random a source of randomness.
         */
        public PartyU(KEMParameters kemParams, AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
        {
            super(algorithmID, partyUInfo, partyVInfo, random);

            if (kemParams instanceof KyberParameters)
            {
                KyberKeyPairGenerator kPg = new KyberKeyPairGenerator();

                kPg.init(new KyberKeyGenerationParameters(random, (KyberParameters)kemParams));

                aKp = kPg.generateKeyPair();

                encSE = new KyberKEMExtractor((KyberPrivateKeyParameters)aKp.getPrivate());
            }
            else if (kemParams instanceof NTRUParameters)
            {
                NTRUKeyPairGenerator kPg = new NTRUKeyPairGenerator();

                kPg.init(new NTRUKeyGenerationParameters(random, (NTRUParameters)kemParams));

                aKp = kPg.generateKeyPair();

                encSE = new NTRUKEMExtractor((NTRUPrivateKeyParameters)aKp.getPrivate());
            }
            else
            {
                throw new IllegalArgumentException("unknown KEMParameters");
            }
        }

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return the current builder instance.
         */
        public PQCOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo)
        {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

            return this;
        }

        public byte[] getSuppPrivInfoPartA()
        {
            return getEncoded(aKp.getPublic());
        }

        public DEROtherInfo generate(byte[] suppPrivInfoPartB)
        {
            this.otherInfoBuilder.withSuppPrivInfo(encSE.extractSecret(suppPrivInfoPartB));

            return otherInfoBuilder.build();
        }
    }

    /**
     * Party V (responder) generation.
     */
    public static class PartyV
        extends PQCOtherInfoGenerator
    {
        private EncapsulatedSecretGenerator encSG;

        /**
         * Create a basic builder with just the compulsory fields for the responder.
         *
         * @param kemParams the key type parameters for populating the private info field.
         * @param algorithmID the algorithm associated with this invocation of the KDF.
         * @param partyUInfo  sender party info.
         * @param partyVInfo  receiver party info.
         * @param random a source of randomness.
         */
        public PartyV(KEMParameters kemParams, AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
        {
            super(algorithmID, partyUInfo, partyVInfo, random);

            if (kemParams instanceof KyberParameters)
            {
                encSG = new KyberKEMGenerator(random);
            }
            else if (kemParams instanceof NTRUParameters)
            {
                encSG = new NTRUKEMGenerator(random);
            }
            else
            {
                throw new IllegalArgumentException("unknown KEMParameters");
            }
        }

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return the current builder instance.
         */
        public PQCOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo)
        {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

            return this;
        }

        public byte[] getSuppPrivInfoPartB(byte[] suppPrivInfoPartA)
        {
            used = false;

            try
            {
                SecretWithEncapsulation bEp = encSG.generateEncapsulated(getPublicKey(suppPrivInfoPartA));

                this.otherInfoBuilder.withSuppPrivInfo(bEp.getSecret());

                return bEp.getEncapsulation();
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("cannot decode public key");
            }
        }

        public DEROtherInfo generate()
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            return otherInfoBuilder.build();
        }
    }

    private static byte[] getEncoded(AsymmetricKeyParameter pubKey)
    {
        try
        {
            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey).getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    private static AsymmetricKeyParameter getPublicKey(byte[] enc)
        throws IOException
    {
        return PublicKeyFactory.createKey(enc);
    }
}
