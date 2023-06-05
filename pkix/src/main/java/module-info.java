module com.distrimind.bouncycastle.pkix {
	requires com.distrimind.bouncycastle.core;
	requires com.distrimind.bouncycastle.util;
	requires com.distrimind.bouncycastle.prov;
	requires java.naming;
	requires java.logging;
	exports com.distrimind.bouncycastle.pkix.jcajce;
	exports com.distrimind.bouncycastle.pkix;
	exports com.distrimind.bouncycastle.operator.bc;
	exports com.distrimind.bouncycastle.operator.jcajce;
	exports com.distrimind.bouncycastle.operator;
	exports com.distrimind.bouncycastle.cert.bc;
	exports com.distrimind.bouncycastle.cert.jcajce;
	exports com.distrimind.bouncycastle.cert.cmp;
	exports com.distrimind.bouncycastle.cert.crmf.bc;
	exports com.distrimind.bouncycastle.cert.crmf.jcajce;
	exports com.distrimind.bouncycastle.cert.crmf;
	exports com.distrimind.bouncycastle.cert.dane.fetcher;
	exports com.distrimind.bouncycastle.cert.dane;
	exports com.distrimind.bouncycastle.cert.ocsp.jcajce;
	exports com.distrimind.bouncycastle.cert.ocsp;
	exports com.distrimind.bouncycastle.cert.path.validations;
	exports com.distrimind.bouncycastle.cert.path;
	exports com.distrimind.bouncycastle.cert.selector.jcajce;
	exports com.distrimind.bouncycastle.cert.selector;
}
