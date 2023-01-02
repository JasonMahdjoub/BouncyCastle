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
	exports com.distrimind.bouncycastle.jce.provider;
	exports com.distrimind.bouncycastle.jcajce;

}