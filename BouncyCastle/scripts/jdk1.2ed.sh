#
# JDK 1.2 edits

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
