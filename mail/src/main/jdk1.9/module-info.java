module com.distrimind.bouncycastle.mail
{
    requires com.distrimind.bouncycastle.provider;
    requires com.distrimind.bouncycastle.pkix;

    exports com.distrimind.bouncycastle.mail.smime;
    exports com.distrimind.bouncycastle.mail.smime.examples;
    exports com.distrimind.bouncycastle.mail.smime.handlers;
    exports com.distrimind.bouncycastle.mail.smime.util;
    exports com.distrimind.bouncycastle.mail.smime.validator;
}
