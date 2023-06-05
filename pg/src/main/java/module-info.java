module com.distrimind.bouncycastle.pg {
	requires com.distrimind.bouncycastle.core;
	requires com.distrimind.bouncycastle.prov;
	requires java.logging;
	exports com.distrimind.bouncycastle.apache.bzip2;
	exports com.distrimind.bouncycastle.gpg.keybox.jcajce;
	exports com.distrimind.bouncycastle.gpg.keybox.bc;
	exports com.distrimind.bouncycastle.gpg.keybox;
	exports com.distrimind.bouncycastle.gpg;
	exports com.distrimind.bouncycastle.bcpg.attr;
	exports com.distrimind.bouncycastle.bcpg.sig;
	exports com.distrimind.bouncycastle.bcpg;
	exports com.distrimind.bouncycastle.openpgp.bc;
	exports com.distrimind.bouncycastle.openpgp.jcajce;
	exports com.distrimind.bouncycastle.openpgp.examples;
	exports com.distrimind.bouncycastle.openpgp.operator.bc;
	exports com.distrimind.bouncycastle.openpgp.operator.jcajce;
	exports com.distrimind.bouncycastle.openpgp.operator;
	exports com.distrimind.bouncycastle.openpgp;
}