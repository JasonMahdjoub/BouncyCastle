#
# JDK 1.2 edits

for i in com/distrimind/bouncycastle/pqc/jcajce/provider/*/*.java  com/distrimind/bouncycastle/pqc/*/*/*.java com/distrimind/bouncycastle/pqc/*/*/*/*.java  com/distrimind/bouncycastle/crypto/digests/*.java com/distrimind/bouncycastle/cert/cmp/*.java com/distrimind/bouncycastle/crypto/engines/*.java com/distrimind/bouncycastle/openpgp/operator/*.java com/distrimind/bouncycastle/openpgp/operator/jcajce/*.java com/distrimind/bouncycastle/openpgp/operator/bc/*.java com/distrimind/bouncycastle/openpgp/*.java com/distrimind/bouncycastle/bcpg/*.java com/distrimind/bouncycastle/openpgp/test/*.java com/distrimind/bouncycastle/bcpg/sig/* com/distrimind/bouncycastle/pkcs/*
do
ed $i <<%%
g/ .Override/d
g/	.Override/d
g/ .Deprecated/d
g/	.Deprecated/d
w
q
%%
done

ed com/distrimind/bouncycastle/cert/crmf/jcajce/JcaCertificateRepMessageBuilder.java <<%
g/\.\.\./s//[]/
w
q
%

ed com/distrimind/bouncycastle/crypto/util/DERMacData.java <<%
g/private final String enc;/s/final//
g/private final int ordinal;/s/final//
g/private final byte.. macData;/s/final//
g/private final DERSequence sequence;/s/final//
w
q
%

ed com/distrimind/bouncycastle/crypto/util/DEROtherInfo.java <<%
g/private final DERSequence sequence;/s/final//
w
q
%

ed com/distrimind/bouncycastle/jcajce/spec/KTSParameterSpec.java <<%
g/private final String wrappingKeyAlgorithm;/s/final//
g/private final int keySizeInBits;/s/final//
g/private final AlgorithmParameterSpec parameterSpec;/s/final//
g/private final AlgorithmIdentifier kdfAlgorithm;/s/final//
w
q
%

ed com/distrimind/bouncycastle/util/test/FixedSecureRandom.java <<%
g/private static final boolean/s/final//
w
q
%

ed com/distrimind/bouncycastle/asn1/cmc/CertificationRequest.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/crypto/util/PBKDF2Config.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/crypto/util/ScryptConfig.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/pqc/crypto/newhope/NHOtherInfoGenerator.java <<%
g/private final/s/final//
g/protected final/s/final//
g/(getPublicKey(/s//(NHOtherInfoGenerator.getPublicKey(/
g/return getEncod/s//return NHOtherInfoGenerator.getEncod/
w
q
%

ed com/distrimind/bouncycastle/crypto/CryptoServicesRegistrar.java <<%
g/private final String/s/final//
g/private final Class/s/final//
w
q
%

ed com/distrimind/bouncycastle/crypto/params/Argon2Parameters.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/cert/crmf/bc/BcCRMFEncryptorBuilder.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/crypto/modes/ChaCha20Poly1305.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/jcajce/provider/drbg/DRBG.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/pqc/crypto/test/TestSampler.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/cms/bc/BcCMSContentEncryptorBuilder.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/crypto/prng/SP800SecureRandomBuilder.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/crypto/modes/GCMSIVBlockCipher.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/cms/CMSSignedDataGenerator.java <<%
g/LinkedHashSet/s//HashSet/g
w
q
%

ed com/distrimind/bouncycastle/cms/CMSAuthEnvelopedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed com/distrimind/bouncycastle/cms/CMSAuthenticatedDataStreamGenerator.java <<%
g/java.util.Collections/s/$/ import java.util.HashMap;/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed com/distrimind/bouncycastle/cms/CMSAuthenticatedDataGenerator.java <<%
g/java.util.Collections/s/$/ import java.util.HashMap;/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed com/distrimind/bouncycastle/cms/CMSEnvelopedDataStreamGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed com/distrimind/bouncycastle/cms/CMSEnvelopedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed com/distrimind/bouncycastle/cms/CMSEncryptedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed com/distrimind/bouncycastle/bcpg/ArmoredOutputStream.java <<%
g/private final/s/final//
g/\\.\\.\\./s//[]/
w
q
%

ed com/distrimind/bouncycastle/bcpg/ArmoredInputStream.java <<%
g/private static final/s/final//
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/openpgp/PGPExtendedKeyAttribute.java <<%
g/private final/s/final//
w
q
%

ed com/distrimind/bouncycastle/gpg/SExpression.java <<%
g/\.\.\. /s//[]/g
w
q
%

ed com/distrimind/bouncycastle/openpgp/operator/jcajce/JcePublicKeyDataDecryptorFactoryBuilder.java <<%
g/RSAKey/s//RSAPrivateKey/g
w
q
%

ed com/distrimind/bouncycastle/openpgp/operator/jcajce/JcePGPDataEncryptorBuilder.java <<%
g/private final/s//private/g
w
q
%

ed com/distrimind/bouncycastle/openpgp/operator/bc/BcPGPDataEncryptorBuilder.java <<%
g/private final/s//private/g
w
q
%

ed com/distrimind/bouncycastle/openpgp/PGPCanonicalizedDataGenerator.java <<%
g/FileNotFoundException/s//IOException/
w
q
%
