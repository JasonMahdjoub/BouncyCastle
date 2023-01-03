module com.distrimind.bouncycastle.prov {
	requires com.distrimind.bouncycastle.core;
	requires java.sql;
	requires java.naming;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.x509;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.util;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.ec;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.dh;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.dsa;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.dstu;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.ecgost;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.ecgost12;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.edec;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.elgamal;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.gost;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.ies;
	exports com.distrimind.bouncycastle.jcajce.provider.asymmetric.rsa;
	exports com.distrimind.bouncycastle.jcajce.provider.util;
	exports com.distrimind.bouncycastle.jcajce.provider.config;
	exports com.distrimind.bouncycastle.jcajce.provider.drbg;
	exports com.distrimind.bouncycastle.jcajce.provider.digest;
	exports com.distrimind.bouncycastle.jcajce.provider.keystore.bc;
	exports com.distrimind.bouncycastle.jcajce.provider.keystore.util;
	exports com.distrimind.bouncycastle.jcajce.provider.keystore.bcfks;
	exports com.distrimind.bouncycastle.jcajce.provider.keystore.pkcs12;
	exports com.distrimind.bouncycastle.jcajce.provider.keystore;
	exports com.distrimind.bouncycastle.jcajce.provider.symmetric.util;
	exports com.distrimind.bouncycastle.jcajce.provider.symmetric;

	exports com.distrimind.bouncycastle.jcajce.io;
	exports com.distrimind.bouncycastle.jcajce.util;
	exports com.distrimind.bouncycastle.jcajce.spec;
	exports com.distrimind.bouncycastle.jcajce.interfaces;
	exports com.distrimind.bouncycastle.jcajce;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.util;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.ntru;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.rainbow;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.bike;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.cmce;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.dilithium;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.falcon;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.frodo;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.gmss;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.hqc;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.kyber;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.lms;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.newhope;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.ntruprime;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.picnic;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.qtesla;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.saber;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.sike;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.sphincs;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.sphincsplus;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider.xmss;
	exports com.distrimind.bouncycastle.pqc.jcajce.provider;
	exports com.distrimind.bouncycastle.pqc.jcajce.spec;
	exports com.distrimind.bouncycastle.pqc.jcajce.interfaces;
	exports com.distrimind.bouncycastle.jce.spec;
	exports com.distrimind.bouncycastle.jce.provider;
	exports com.distrimind.bouncycastle.jce.interfaces;
	exports com.distrimind.bouncycastle.jce.exception;
	exports com.distrimind.bouncycastle.jce.netscape;
	exports com.distrimind.bouncycastle.jce;
	exports com.distrimind.bouncycastle.x509.util;
	exports com.distrimind.bouncycastle.x509.extension;
	exports com.distrimind.bouncycastle.x509;

}