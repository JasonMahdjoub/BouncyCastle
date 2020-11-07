module com.distrimind.bouncycastle.tls
{
    provides java.security.Provider with com.distrimind.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
    
    requires java.logging;
    requires com.distrimind.bouncycastle.provider;
    
    exports com.distrimind.bouncycastle.jsse;
    exports com.distrimind.bouncycastle.tls;
    exports com.distrimind.bouncycastle.jsse.provider;
    exports com.distrimind.bouncycastle.jsse.java.security;
    exports com.distrimind.bouncycastle.tls.crypto;
    exports com.distrimind.bouncycastle.tls.crypto.impl;
    exports com.distrimind.bouncycastle.tls.crypto.impl.bc;
    exports com.distrimind.bouncycastle.tls.crypto.impl.jcajce;
    exports com.distrimind.bouncycastle.tls.crypto.impl.jcajce.srp;
}
