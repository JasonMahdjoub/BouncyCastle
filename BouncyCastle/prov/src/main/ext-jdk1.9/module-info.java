module org.bouncycastle.provider
{
    requires java.sql;
    requires java.naming;

    opens org.bouncycastle.jcajce.provider.asymmetric.edec to java.base;
    opens org.bouncycastle.pqc.jcajce.provider.qtesla to java.base;

    exports org.bouncycastle;
    exports org.bouncycastle.bcasn1;
    exports org.bouncycastle.bcasn1.anssi;
    exports org.bouncycastle.bcasn1.bc;
    exports org.bouncycastle.bcasn1.bsi;
    exports org.bouncycastle.bcasn1.cmc;
    exports org.bouncycastle.bcasn1.cmp;
    exports org.bouncycastle.bcasn1.cms;
    exports org.bouncycastle.bcasn1.cms.ecc;
    exports org.bouncycastle.bcasn1.crmf;
    exports org.bouncycastle.bcasn1.cryptopro;
    exports org.bouncycastle.bcasn1.dvcs;
    exports org.bouncycastle.bcasn1.eac;
    exports org.bouncycastle.bcasn1.edec;
    exports org.bouncycastle.bcasn1.esf;
    exports org.bouncycastle.bcasn1.ess;
    exports org.bouncycastle.bcasn1.est;
    exports org.bouncycastle.bcasn1.gm;
    exports org.bouncycastle.bcasn1.gnu;
    exports org.bouncycastle.bcasn1.iana;
    exports org.bouncycastle.bcasn1.icao;
    exports org.bouncycastle.bcasn1.isismtt;
    exports org.bouncycastle.bcasn1.isismtt.ocsp;
    exports org.bouncycastle.bcasn1.isismtt.x509;
    exports org.bouncycastle.bcasn1.iso;
    exports org.bouncycastle.bcasn1.kisa;
    exports org.bouncycastle.bcasn1.microsoft;
    exports org.bouncycastle.bcasn1.misc;
    exports org.bouncycastle.bcasn1.mozilla;
    exports org.bouncycastle.bcasn1.nist;
    exports org.bouncycastle.bcasn1.nsri;
    exports org.bouncycastle.bcasn1.ntt;
    exports org.bouncycastle.bcasn1.ocsp;
    exports org.bouncycastle.bcasn1.oiw;
    exports org.bouncycastle.bcasn1.pkcs;
    exports org.bouncycastle.bcasn1.rosstandart;
    exports org.bouncycastle.bcasn1.sec;
    exports org.bouncycastle.bcasn1.smime;
    exports org.bouncycastle.bcasn1.teletrust;
    exports org.bouncycastle.bcasn1.tsp;
    exports org.bouncycastle.bcasn1.ua;
    exports org.bouncycastle.bcasn1.util;
    exports org.bouncycastle.bcasn1.x500;
    exports org.bouncycastle.bcasn1.x500.style;
    exports org.bouncycastle.bcasn1.x509;
    exports org.bouncycastle.bcasn1.x509.qualified;
    exports org.bouncycastle.bcasn1.x509.sigi;
    exports org.bouncycastle.bcasn1.x9;
    exports org.bouncycastle.bccrypto;
    exports org.bouncycastle.bccrypto.agreement;
    exports org.bouncycastle.bccrypto.agreement.jpake;
    exports org.bouncycastle.bccrypto.agreement.kdf;
    exports org.bouncycastle.bccrypto.agreement.srp;
    exports org.bouncycastle.bccrypto.commitments;
    exports org.bouncycastle.bccrypto.digests;
    exports org.bouncycastle.bccrypto.ec;
    exports org.bouncycastle.bccrypto.encodings;
    exports org.bouncycastle.bccrypto.engines;
    exports org.bouncycastle.bccrypto.examples;
    exports org.bouncycastle.bccrypto.generators;
    exports org.bouncycastle.bccrypto.io;
    exports org.bouncycastle.bccrypto.kems;
    exports org.bouncycastle.bccrypto.macs;
    exports org.bouncycastle.bccrypto.modes;
    exports org.bouncycastle.bccrypto.modes.gcm;
    exports org.bouncycastle.bccrypto.modes.kgcm;
    exports org.bouncycastle.bccrypto.paddings;
    exports org.bouncycastle.bccrypto.params;
    exports org.bouncycastle.bccrypto.parsers;
    exports org.bouncycastle.bccrypto.prng;
    exports org.bouncycastle.bccrypto.prng.drbg;
    exports org.bouncycastle.bccrypto.signers;
    exports org.bouncycastle.bccrypto.tls;
    exports org.bouncycastle.bccrypto.util;
    exports org.bouncycastle.i18n;
    exports org.bouncycastle.i18n.filter;
    exports org.bouncycastle.iana;
    exports org.bouncycastle.jcajce;
    exports org.bouncycastle.jcajce.io;
    exports org.bouncycastle.jcajce.provider.asymmetric;
    exports org.bouncycastle.jcajce.provider.asymmetric.dh;
    exports org.bouncycastle.jcajce.provider.asymmetric.dsa;
    exports org.bouncycastle.jcajce.provider.asymmetric.dstu;
    exports org.bouncycastle.jcajce.provider.asymmetric.ec;
    exports org.bouncycastle.jcajce.provider.asymmetric.ecgost;
    exports org.bouncycastle.jcajce.provider.asymmetric.ecgost12;
    exports org.bouncycastle.jcajce.provider.asymmetric.elgamal;
    exports org.bouncycastle.jcajce.provider.asymmetric.gost;
    exports org.bouncycastle.jcajce.provider.asymmetric.ies;
    exports org.bouncycastle.jcajce.provider.asymmetric.rsa;
    exports org.bouncycastle.jcajce.provider.asymmetric.util;
    exports org.bouncycastle.jcajce.provider.asymmetric.x509;
    exports org.bouncycastle.jcajce.provider.config;
    exports org.bouncycastle.jcajce.provider.digest;
    exports org.bouncycastle.jcajce.provider.drbg;
    exports org.bouncycastle.jcajce.provider.keystore;
    exports org.bouncycastle.jcajce.provider.keystore.bc;
    exports org.bouncycastle.jcajce.provider.keystore.bcfks;
    exports org.bouncycastle.jcajce.provider.keystore.pkcs12;
    exports org.bouncycastle.jcajce.provider.symmetric;
    exports org.bouncycastle.jcajce.provider.symmetric.util;
    exports org.bouncycastle.jcajce.provider.util;
    exports org.bouncycastle.jcajce.spec;
    exports org.bouncycastle.jcajce.util;
    exports org.bouncycastle.jce;
    exports org.bouncycastle.jce.exception;
    exports org.bouncycastle.jce.interfaces;
    exports org.bouncycastle.jce.netscape;
    exports org.bouncycastle.jce.provider;
    exports org.bouncycastle.jce.spec;
    exports org.bouncycastle.bcmath;
    exports org.bouncycastle.bcmath.ec;
    exports org.bouncycastle.bcmath.ec.custom.djb;
    exports org.bouncycastle.bcmath.ec.custom.gm;
    exports org.bouncycastle.bcmath.ec.custom.sec;
    exports org.bouncycastle.bcmath.ec.endo;
    exports org.bouncycastle.bcmath.ec.rfc7748;
    exports org.bouncycastle.bcmath.ec.rfc8032;
    exports org.bouncycastle.bcmath.ec.tools;
    exports org.bouncycastle.bcmath.field;
    exports org.bouncycastle.bcmath.raw;
    exports org.bouncycastle.pqc.asn1;
    exports org.bouncycastle.pqc.crypto;
    exports org.bouncycastle.pqc.crypto.gmss;
    exports org.bouncycastle.pqc.crypto.gmss.util;
    exports org.bouncycastle.pqc.crypto.mceliece;
    exports org.bouncycastle.pqc.crypto.newhope;
    exports org.bouncycastle.pqc.crypto.ntru;
    exports org.bouncycastle.pqc.crypto.rainbow;
    exports org.bouncycastle.pqc.crypto.rainbow.util;
    exports org.bouncycastle.pqc.crypto.sphincs;
    exports org.bouncycastle.pqc.crypto.xmss;
    exports org.bouncycastle.pqc.jcajce.interfaces;
    exports org.bouncycastle.pqc.jcajce.provider;
    exports org.bouncycastle.pqc.jcajce.provider.gmss;
    exports org.bouncycastle.pqc.jcajce.provider.mceliece;
    exports org.bouncycastle.pqc.jcajce.provider.newhope;
    exports org.bouncycastle.pqc.jcajce.provider.rainbow;
    exports org.bouncycastle.pqc.jcajce.provider.sphincs;
    exports org.bouncycastle.pqc.jcajce.provider.util;
    exports org.bouncycastle.pqc.jcajce.provider.xmss;
    exports org.bouncycastle.pqc.jcajce.spec;
    exports org.bouncycastle.pqc.math.linearalgebra;
    exports org.bouncycastle.pqc.math.ntru.euclid;
    exports org.bouncycastle.pqc.math.ntru.polynomial;
    exports org.bouncycastle.pqc.math.ntru.util;
    exports org.bouncycastle.bcutil;
    exports org.bouncycastle.bcutil.encoders;
    exports org.bouncycastle.bcutil.io;
    exports org.bouncycastle.bcutil.io.pem;
    exports org.bouncycastle.bcutil.test;
    exports org.bouncycastle.x509;
    exports org.bouncycastle.x509.extension;
    exports org.bouncycastle.x509.util;
}
