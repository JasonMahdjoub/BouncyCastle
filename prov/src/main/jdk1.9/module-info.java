module com.distrimind.bouncycastle.provider
{
    requires java.sql;
    requires java.naming;

    provides java.security.Provider with com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider,com.distrimind.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

    opens com.distrimind.bouncycastle.jcajce.provider.asymmetric.edec to java.base;
    opens com.distrimind.bouncycastle.pqc.jcajce.provider.lms to java.base;
    opens com.distrimind.bouncycastle.pqc.jcajce.provider.falcon to java.base;
    opens com.distrimind.bouncycastle.pqc.jcajce.provider.dilithium to java.base;

    exports com.distrimind.bouncycastle;
    exports com.distrimind.bouncycastle.asn1;
    exports com.distrimind.bouncycastle.asn1.anssi;
    exports com.distrimind.bouncycastle.asn1.bc;
    exports com.distrimind.bouncycastle.asn1.cryptopro;
    exports com.distrimind.bouncycastle.asn1.cryptlib;
    exports com.distrimind.bouncycastle.asn1.edec;
    exports com.distrimind.bouncycastle.asn1.gm;
    exports com.distrimind.bouncycastle.asn1.gnu;
    exports com.distrimind.bouncycastle.asn1.iana;
    exports com.distrimind.bouncycastle.asn1.isara;
    exports com.distrimind.bouncycastle.asn1.iso;
    exports com.distrimind.bouncycastle.asn1.kisa;
    exports com.distrimind.bouncycastle.asn1.microsoft;
    exports com.distrimind.bouncycastle.asn1.misc;
    exports com.distrimind.bouncycastle.asn1.mozilla;
    exports com.distrimind.bouncycastle.asn1.nist;
    exports com.distrimind.bouncycastle.asn1.nsri;
    exports com.distrimind.bouncycastle.asn1.ntt;
    exports com.distrimind.bouncycastle.asn1.ocsp;
    exports com.distrimind.bouncycastle.asn1.oiw;
    exports com.distrimind.bouncycastle.asn1.pkcs;
    exports com.distrimind.bouncycastle.asn1.rosstandart;
    exports com.distrimind.bouncycastle.asn1.sec;
    exports com.distrimind.bouncycastle.asn1.teletrust;
    exports com.distrimind.bouncycastle.asn1.ua;
    exports com.distrimind.bouncycastle.asn1.util;
    exports com.distrimind.bouncycastle.asn1.x500;
    exports com.distrimind.bouncycastle.asn1.x500.style;
    exports com.distrimind.bouncycastle.asn1.x509;
    exports com.distrimind.bouncycastle.asn1.x509.qualified;
    exports com.distrimind.bouncycastle.asn1.x509.sigi;
    exports com.distrimind.bouncycastle.asn1.x9;
    exports com.distrimind.bouncycastle.crypto;
    exports com.distrimind.bouncycastle.crypto.agreement;
    exports com.distrimind.bouncycastle.crypto.agreement.jpake;
    exports com.distrimind.bouncycastle.crypto.agreement.kdf;
    exports com.distrimind.bouncycastle.crypto.agreement.srp;
    exports com.distrimind.bouncycastle.crypto.commitments;
    exports com.distrimind.bouncycastle.crypto.constraints;
    exports com.distrimind.bouncycastle.crypto.digests;
    exports com.distrimind.bouncycastle.crypto.ec;
    exports com.distrimind.bouncycastle.crypto.encodings;
    exports com.distrimind.bouncycastle.crypto.engines;
    exports com.distrimind.bouncycastle.crypto.examples;
    exports com.distrimind.bouncycastle.crypto.generators;
    exports com.distrimind.bouncycastle.crypto.hpke;
    exports com.distrimind.bouncycastle.crypto.io;
    exports com.distrimind.bouncycastle.crypto.kems;
    exports com.distrimind.bouncycastle.crypto.macs;
    exports com.distrimind.bouncycastle.crypto.modes;
    exports com.distrimind.bouncycastle.crypto.modes.gcm;
    exports com.distrimind.bouncycastle.crypto.modes.kgcm;
    exports com.distrimind.bouncycastle.crypto.paddings;
    exports com.distrimind.bouncycastle.crypto.params;
    exports com.distrimind.bouncycastle.crypto.parsers;
    exports com.distrimind.bouncycastle.crypto.prng;
    exports com.distrimind.bouncycastle.crypto.prng.drbg;
    exports com.distrimind.bouncycastle.crypto.signers;
    exports com.distrimind.bouncycastle.crypto.util;
    exports com.distrimind.bouncycastle.i18n;
    exports com.distrimind.bouncycastle.i18n.filter;
    exports com.distrimind.bouncycastle.iana;
    exports com.distrimind.bouncycastle.jcajce;
    exports com.distrimind.bouncycastle.jcajce.io;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.dh;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.dsa;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.dstu;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.ec;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.edec;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.ecgost;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.ecgost12;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.elgamal;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.gost;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.ies;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.rsa;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.util;
    exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.x509;
    exports com.distrimind.bouncycastle.jcajce.provider.config;
    exports com.distrimind.bouncycastle.jcajce.provider.digest;
    exports com.distrimind.bouncycastle.jcajce.provider.drbg;
    exports com.distrimind.bouncycastle.jcajce.provider.keystore;
    exports com.distrimind.bouncycastle.jcajce.provider.keystore.bc;
    exports com.distrimind.bouncycastle.jcajce.provider.keystore.bcfks;
    exports com.distrimind.bouncycastle.jcajce.provider.keystore.pkcs12;
    exports com.distrimind.bouncycastle.jcajce.provider.symmetric;
    exports com.distrimind.bouncycastle.jcajce.provider.symmetric.util;
    exports com.distrimind.bouncycastle.jcajce.provider.util;
    exports com.distrimind.bouncycastle.jcajce.interfaces;
    exports com.distrimind.bouncycastle.jcajce.spec;
    exports com.distrimind.bouncycastle.jcajce.util;
    exports com.distrimind.bouncycastle.jce;
    exports com.distrimind.bouncycastle.jce.exception;
    exports com.distrimind.bouncycastle.jce.interfaces;
    exports com.distrimind.bouncycastle.jce.netscape;
    exports com.distrimind.bouncycastle.jce.provider;
    exports com.distrimind.bouncycastle.jce.spec;
    exports com.distrimind.bouncycastle.math;
    exports com.distrimind.bouncycastle.math.ec;
    exports com.distrimind.bouncycastle.math.ec.custom.djb;
    exports com.distrimind.bouncycastle.math.ec.custom.gm;
    exports com.distrimind.bouncycastle.math.ec.custom.sec;
    exports com.distrimind.bouncycastle.math.ec.endo;
    exports com.distrimind.bouncycastle.math.ec.rfc7748;
    exports com.distrimind.bouncycastle.math.ec.rfc8032;
    exports com.distrimind.bouncycastle.math.ec.tools;
    exports com.distrimind.bouncycastle.math.field;
    exports com.distrimind.bouncycastle.math.raw;
    exports com.distrimind.bouncycastle.pqc.asn1;
    exports com.distrimind.bouncycastle.pqc.crypto;
    exports com.distrimind.bouncycastle.pqc.crypto.bike;
    exports com.distrimind.bouncycastle.pqc.crypto.cmce;
    exports com.distrimind.bouncycastle.pqc.crypto.crystals.dilithium;
    exports com.distrimind.bouncycastle.pqc.crypto.crystals.kyber;
    exports com.distrimind.bouncycastle.pqc.crypto.falcon;
    exports com.distrimind.bouncycastle.pqc.crypto.frodo;
    exports com.distrimind.bouncycastle.crypto.fpe;
    exports com.distrimind.bouncycastle.pqc.crypto.gemss;
    exports com.distrimind.bouncycastle.pqc.crypto.hqc;
    exports com.distrimind.bouncycastle.pqc.crypto.lms;
    exports com.distrimind.bouncycastle.pqc.crypto.newhope;
    exports com.distrimind.bouncycastle.pqc.crypto.ntru;
    exports com.distrimind.bouncycastle.pqc.crypto.ntruprime;
    exports com.distrimind.bouncycastle.pqc.crypto.picnic;
    exports com.distrimind.bouncycastle.pqc.crypto.rainbow;
    exports com.distrimind.bouncycastle.pqc.crypto.saber;
    exports com.distrimind.bouncycastle.pqc.crypto.sphincs;
    exports com.distrimind.bouncycastle.pqc.crypto.sphincsplus;
    exports com.distrimind.bouncycastle.pqc.crypto.util;
    exports com.distrimind.bouncycastle.pqc.crypto.xmss;
    exports com.distrimind.bouncycastle.pqc.math.ntru;
    exports com.distrimind.bouncycastle.pqc.math.ntru.parameters;
    exports com.distrimind.bouncycastle.pqc.jcajce.interfaces;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.bike;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.cmce;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.dilithium;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.falcon;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.frodo;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.gmss;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.hqc;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.kyber;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.lms;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.ntru;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.ntruprime;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.newhope;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.picnic;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.rainbow;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.saber;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.sphincs;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.sphincsplus;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.util;
    exports com.distrimind.bouncycastle.pqc.jcajce.provider.xmss;
    exports com.distrimind.bouncycastle.pqc.jcajce.spec;
    exports com.distrimind.bouncycastle.pqc.legacy.crypto.gmss;
    exports com.distrimind.bouncycastle.pqc.legacy.crypto.gmss.util;
    exports com.distrimind.bouncycastle.pqc.legacy.crypto.qtesla;
    exports com.distrimind.bouncycastle.pqc.legacy.crypto.mceliece;
    exports com.distrimind.bouncycastle.pqc.legacy.crypto.rainbow;
    exports com.distrimind.bouncycastle.pqc.legacy.crypto.rainbow.util;
    exports com.distrimind.bouncycastle.pqc.legacy.math.linearalgebra;
    exports com.distrimind.bouncycastle.util;
    exports com.distrimind.bouncycastle.util.encoders;
    exports com.distrimind.bouncycastle.util.io;
    exports com.distrimind.bouncycastle.util.io.pem;
    exports com.distrimind.bouncycastle.util.test;
    exports com.distrimind.bouncycastle.x509;
    exports com.distrimind.bouncycastle.x509.extension;
    exports com.distrimind.bouncycastle.x509.util;

}
