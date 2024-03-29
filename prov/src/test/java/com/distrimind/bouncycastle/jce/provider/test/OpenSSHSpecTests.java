package com.distrimind.bouncycastle.jce.provider.test;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;

import com.distrimind.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import com.distrimind.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Base64;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.io.pem.PemReader;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class OpenSSHSpecTests
    extends SimpleTest
{
    private static final SecureRandom secureRandom = new SecureRandom();

    public void testEncodingRSA()
        throws Exception
    {
        byte[] rawPub = Base64.decode("AAAAB3NzaC1yc2EAAAADAQABAAAAgQDvh2BophdIp8ojwGZQR0FQ/awowXnV24nAPm+/na8MOUrdySNhOnlek4LAZl82/+Eu2t21XD6hQUiHKAj6XaNFBthTuss7Cz/tA348DLEMHD9wUtT0FXVmsxqN4BfusunbcULxxVWG2z8FvqeaGgc/Unkp9y7/kyf54pPUCBcClw==");
        byte[] rawPriv = new PemReader(new StringReader("-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXgIBAAKBgQDvh2BophdIp8ojwGZQR0FQ/awowXnV24nAPm+/na8MOUrdySNh\n" +
            "Onlek4LAZl82/+Eu2t21XD6hQUiHKAj6XaNFBthTuss7Cz/tA348DLEMHD9wUtT0\n" +
            "FXVmsxqN4BfusunbcULxxVWG2z8FvqeaGgc/Unkp9y7/kyf54pPUCBcClwIDAQAB\n" +
            "AoGBAOMXYEoXHgAeREE9CkOWKtDUkEJbnF0rNSB0kZIDt5BJSTeYmNh3jdYi2FX9\n" +
            "OMx2MFIx4v0tJZvQvyiUxl5IJJ9ZJsYUWF+6VbcTVwYYfdVzZzP2TNyGmF9/ADZW\n" +
            "wBehqP04uRlYjt94kqb4HoOKF3gJ3LC4uW9xcEltTBeHWCfhAkEA/2biF5St9/Ya\n" +
            "540E4zu/FKPsxLSaT8LWCo9+X7IqIzlBQCB4GjM+nZeTm7eZOkfAFZoxwfiNde/9\n" +
            "qleXXf6B2QJBAPAW+jDBC3QF4/g8n9cDxm/A3ICmcOFSychLSrydk9ZyRPbTRyQC\n" +
            "YlC2mf/pCrO/yO7h189BXyQ3PXOEhnujce8CQQD7gDy0K90EiH0F94AQpA0OLj5B\n" +
            "lfc/BAXycEtpwPBtrzvqAg9C/aNzXIgmly10jqNAoo7NDA2BTcrlq0uLa8xBAkBl\n" +
            "7Hs+I1XnZXDIO4Rn1VRysN9rRj15ipnbDAuoUwUl7tDUMBFteg2e0kZCW/6NHIgC\n" +
            "0aG6fLgVOdY+qi4lYtfFAkEAqqiBgEgSrDmnJLTm6j/Pv1mBA6b9bJbjOqomrDtr\n" +
            "AWTXe+/kSCv/jYYdpNA/tDgAwEmtkWWEie6+SwJB5cXXqg==\n" +
            "-----END RSA PRIVATE KEY-----\n")).readPemObject().getContent();


        OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(rawPub);
        OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);

        isEquals("Pk type", pubSpec.getType(), "ssh-rsa");
        isEquals("Spec Type", privSpec.getFormat(), "ASN.1");


        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);

        originalMessage[0] |= 1;

        KeyFactory kpf = KeyFactory.getInstance("RSA", "BC");

        PublicKey pk = kpf.generatePublic(pubSpec);
        PrivateKey prk = kpf.generatePrivate(privSpec);

        OpenSSHPublicKeySpec rcPublicKeySpec = (OpenSSHPublicKeySpec)kpf.getKeySpec(pk, OpenSSHPublicKeySpec.class);
        OpenSSHPrivateKeySpec rcPrivateSpec = (OpenSSHPrivateKeySpec)kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);

        isEquals("Pk type", rcPublicKeySpec.getType(), "ssh-rsa");
        isEquals("Spec Type", rcPrivateSpec.getFormat(), "ASN.1");

        isTrue("RSAPublic key not same", Arrays.areEqual(rawPub, rcPublicKeySpec.getEncoded()));
        isTrue("RSAPrivate key not same", Arrays.areEqual(rawPriv, rcPrivateSpec.getEncoded()));

        String rsa2048Key =
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
          + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n"
          + "NhAAAAAwEAAQAAAQEArxWa1zW+Uf0lUrYoL1yqgTYUT1TfUkfojrhguPB1s/1AEMj8sueu\n"
          + "YDtLozZW/GB+KwO+nzC48CmqsCbCEOqalmdRIQCCQIBs776c0KLnhqzHCmj0Q+6gM0KvUG\n"
          + "z8elzJ8LZuTj5xGRDvFxli4yl2M119X7K2JMci18N95rszioxDECSWg2Arvd25kMKBK5MA\n"
          + "qJjosvxr46soRmxiAHeGzinoLXgpLh9axwySpJ0WVGPl079ZtaYs/XpSoh9HXqCgwnsVy9\n"
          + "JscWbmtaAktjMw2zTfOvmFs9PVJXtXQRzP4nvtT6myK/7v8tPeg8yLnAot9erklHcUOEyb\n"
          + "1LsOrk68+QAAA8j/Xs/E/17PxAAAAAdzc2gtcnNhAAABAQCvFZrXNb5R/SVStigvXKqBNh\n"
          + "RPVN9SR+iOuGC48HWz/UAQyPyy565gO0ujNlb8YH4rA76fMLjwKaqwJsIQ6pqWZ1EhAIJA\n"
          + "gGzvvpzQoueGrMcKaPRD7qAzQq9QbPx6XMnwtm5OPnEZEO8XGWLjKXYzXX1fsrYkxyLXw3\n"
          + "3muzOKjEMQJJaDYCu93bmQwoErkwComOiy/GvjqyhGbGIAd4bOKegteCkuH1rHDJKknRZU\n"
          + "Y+XTv1m1piz9elKiH0deoKDCexXL0mxxZua1oCS2MzDbNN86+YWz09Ule1dBHM/ie+1Pqb\n"
          + "Ir/u/y096DzIucCi316uSUdxQ4TJvUuw6uTrz5AAAAAwEAAQAAAQBPpNBO3Y+51CHKQjp9\n"
          + "cPXO2T7b54u+7h8H7S9ycU/ZlHY0LHlnGKTl+ZMqp2liXLKH9qgb2hoGha2ze64D6/RuPo\n"
          + "lVLdoSZVkopdjHv5L6XFYekierTz1olAkT2L/xGYxzB0meJiFkeaOJKm8lTpMKQpjpk23v\n"
          + "xPZAmBkJgFatyueHaVWGYp0KzUDpdMcS97R6CWCGrYlAUP3F1meC9+Sb3d94qxeqLZsgEn\n"
          + "PYJs1Q7fyL4jYBYm9/pA9O5RLKMQwqY7Qln7l2XTyhavZCIxTmAa6lEf32yB3+EoQR+YEz\n"
          + "eCXXSClbMcnnx83jYyV5uNxN27VJAlgeN7J2ZyJTLlKRAAAAgAUnKuxYaYezMWyBShwR4N\n"
          + "eVAW8vT3CBxsMR/v3u6XmLTzjq4r0gKCxofnnj972uK0LvyTZ21/00MSl0KaAjJySl2hLj\n"
          + "BNQA3TcDXnLEc5KcsKZdDhuWkHGmaoajDp/okfQd6CxuKaBKG/OFdbYqVgOOVeACUUWxT4\n"
          + "NN4e3CxTWQAAAAgQDV3vzDCQanGAXMKZSxfHUU63Tmh+2NcB1I6Sb0/CwpBgLH1y0CTB9r\n"
          + "c8TLSs6HoHx1lfzOp6Yj7BQ9CWHS94Mi+RYBF+SpaMLoZKqCU4Q3UWiHiOyPnMaohAdvRE\n"
          + "gJkaY2OAkFaaCI31rwBrs6b5U/ErtRTUZNJEI7OCi6wDBfBwAAAIEA0ZKyuUW5+VFcTyuR\n"
          + "1G0ky5uihtJryFCjA2fzu7tgobm0gsIgSDClp9TdMh5CDyJo0R9fQnH8Lki0Ku+jgc4X+a\n"
          + "/XMw47d1iL7Hdu9NAJsplezKD5Unso4xJRXhLnXUT5FT8lSgwE+9xUBuILKUmZQa20ejKM\n"
          + "20U6szOxEEclA/8AAAAObWFya0BiYXJuYWNsZXMBAgMEBQ==\n"
          + "-----END OPENSSH PRIVATE KEY-----\n";

        rcPrivateSpec = new OpenSSHPrivateKeySpec(new PemReader(new StringReader(rsa2048Key)).readPemObject().getContent());

        isEquals("Spec Type", rcPrivateSpec.getFormat(), "OpenSSH");

        prk = kpf.generatePrivate(rcPrivateSpec);
        isEquals("pub exponent", ((RSAPrivateCrtKey)prk).getPublicExponent(), new BigInteger("10001", 16));
    }

    public void testEncodingDSA()
        throws Exception
    {
        byte[] rawPub = Base64.decode("AAAAB3NzaC1kc3MAAACBAJBB5+S4kZZYZLswaQ/zm3GM7YWmHsumwo/Xxu+z6Cg2l5PUoiBBZ4ET9EhhQuL2ja/zrCMCi0ZwiSRuSp36ayPrHLbNJb3VdOuJg8xExRa6F3YfVZfcTPUEKh6FU72fI31HrQmi4rpyHnWxL/iDX496ZG2Hdq6UkPISQpQwj4TtAAAAFQCP9TXcVahR/2rpfEhvdXR0PfhbRwAAAIBdXzAVqoOtb9zog6lNF1cGS1S06W9W/clvuwq2xF1s3bkoI/xUbFSc0IAPsGl2kcB61PAZqcop50lgpvYzt8cq/tbqz3ypq1dCQ0xdmJHj975QsRFax+w6xQ0kgpBhwcS2EOizKb+C+tRzndGpcDSoSMuVXp9i4wn5pJSTZxAYFQAAAIEAhQZc687zYxrEDR/1q6m4hw5GFxuVvLsC+bSHtMF0c11Qy4IPg7mBeP7K5Kq4WyJPtmZhuc5Bb12bJQR6qgd1uLn692fe1UK2kM6eWXBzhlzZ54BslfSKHGNN4qH+ln3Zaf/4rpKE7fvoinkrgkOZmj0PMx9D6wlpHKkXMUxeXtc=");
        byte[] rawPriv = new PemReader(new StringReader("-----BEGIN DSA PRIVATE KEY-----\n" +
            "MIIBuwIBAAKBgQCQQefkuJGWWGS7MGkP85txjO2Fph7LpsKP18bvs+goNpeT1KIg\n" +
            "QWeBE/RIYULi9o2v86wjAotGcIkkbkqd+msj6xy2zSW91XTriYPMRMUWuhd2H1WX\n" +
            "3Ez1BCoehVO9nyN9R60JouK6ch51sS/4g1+PemRth3aulJDyEkKUMI+E7QIVAI/1\n" +
            "NdxVqFH/aul8SG91dHQ9+FtHAoGAXV8wFaqDrW/c6IOpTRdXBktUtOlvVv3Jb7sK\n" +
            "tsRdbN25KCP8VGxUnNCAD7BpdpHAetTwGanKKedJYKb2M7fHKv7W6s98qatXQkNM\n" +
            "XZiR4/e+ULERWsfsOsUNJIKQYcHEthDosym/gvrUc53RqXA0qEjLlV6fYuMJ+aSU\n" +
            "k2cQGBUCgYEAhQZc687zYxrEDR/1q6m4hw5GFxuVvLsC+bSHtMF0c11Qy4IPg7mB\n" +
            "eP7K5Kq4WyJPtmZhuc5Bb12bJQR6qgd1uLn692fe1UK2kM6eWXBzhlzZ54BslfSK\n" +
            "HGNN4qH+ln3Zaf/4rpKE7fvoinkrgkOZmj0PMx9D6wlpHKkXMUxeXtcCFELnLOJ8\n" +
            "D0akSCUFY/iDLo/KnOIH\n" +
            "-----END DSA PRIVATE KEY-----\n")).readPemObject().getContent();


        OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(rawPub);
        OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);

        isEquals("Pk type", pubSpec.getType(), "ssh-dss");
        isEquals("Spec Type", privSpec.getFormat(), "ASN.1");


        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);


        originalMessage[0] |= 1;

        KeyFactory kpf = KeyFactory.getInstance("DSA", "BC");

        PublicKey pk = kpf.generatePublic(pubSpec);
        PrivateKey prk = kpf.generatePrivate(privSpec);

        OpenSSHPublicKeySpec dsaPublicKeySpec = (OpenSSHPublicKeySpec)kpf.getKeySpec(pk, OpenSSHPublicKeySpec.class);
        OpenSSHPrivateKeySpec dsaPrivateSpec = (OpenSSHPrivateKeySpec)kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);

        isEquals("Pk type", dsaPublicKeySpec.getType(), "ssh-dss");
        isEquals("Spec Type", dsaPrivateSpec.getFormat(), "ASN.1");

        isTrue("DSA Public key not same", Arrays.areEqual(rawPub, dsaPublicKeySpec.getEncoded()));
        isTrue("DSA Private key not same", Arrays.areEqual(rawPriv, dsaPrivateSpec.getEncoded()));

    }

    private void testEncodingECDSA()
        throws Exception
    {
        byte[] rawPub = Base64.decode("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHq5qxGqnh93Gpbj2w1Avx1UwBl6z5bZC3Viog1yNHDZYcV6Da4YQ3i0/hN7xY7sUy9dNF6g16tJSYXQQ4tvO3g=");
        byte[] rawPriv = new PemReader(new StringReader("-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEIHeg/+m02j6nr4bO8ubfbzhs0fqOjiuIoWbvGnVg+FmpoAoGCCqGSM49\n" +
            "AwEHoUQDQgAEermrEaqeH3caluPbDUC/HVTAGXrPltkLdWKiDXI0cNlhxXoNrhhD\n" +
            "eLT+E3vFjuxTL100XqDXq0lJhdBDi287eA==\n" +
            "-----END EC PRIVATE KEY-----\n")).readPemObject().getContent();

        OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(rawPub);
        OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);

        isEquals("ecdsa-sha2-nistp256", pubSpec.getType());
        isEquals("Spec Type", privSpec.getFormat(), "ASN.1");

        KeyFactory kpf = KeyFactory.getInstance("EC", "BC");

        PublicKey pk = kpf.generatePublic(pubSpec);
        PrivateKey prk = kpf.generatePrivate(privSpec);

        OpenSSHPublicKeySpec ecdsaPublicKeySpec = (OpenSSHPublicKeySpec)kpf.getKeySpec(pk, OpenSSHPublicKeySpec.class);
        OpenSSHPrivateKeySpec ecdsaPrivateSpec = (OpenSSHPrivateKeySpec)kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);

        isEquals("Spec Type", ecdsaPrivateSpec.getFormat(), "ASN.1");

        isTrue("ECPublic key not same", Arrays.areEqual(rawPub, ecdsaPublicKeySpec.getEncoded()));
        isTrue("ECPrivate key not same", Arrays.areEqual(rawPriv, ecdsaPrivateSpec.getEncoded()));

        isEquals("ecdsa-sha2-nistp256", ecdsaPublicKeySpec.getType());
    }

    public void testED25519()
        throws Exception
    {
        byte[] rawPub = Base64.decode("AAAAC3NzaC1lZDI1NTE5AAAAIM4CaV7WQcy0lht0hclgXf4Olyvzvv2fnUvQ3J8IYsWF");
        byte[] rawPriv = new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQAAAKBTr4PvU6+D\n" +
            "7wAAAAtzc2gtZWQyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQ\n" +
            "AAAED4BTHeR3YD7CFQqusztfL5K+YSD4mRGLBwb7jHiXxIJM4CaV7WQcy0lht0hclgXf4O\n" +
            "lyvzvv2fnUvQ3J8IYsWFAAAAG21lZ2Fud29vZHNAdHljaGUtMzI2NS5sb2NhbAEC\n" +
            "-----END OPENSSH PRIVATE KEY-----\n")).readPemObject().getContent();

        OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(rawPub);
        OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);

        isEquals("Pk type", pubSpec.getType(), "ssh-ed25519");
        isEquals("Spec Type", privSpec.getFormat(), "OpenSSH");

        KeyFactory kpf = KeyFactory.getInstance("ED25519", "BC");

        PublicKey pk = kpf.generatePublic(pubSpec);
        PrivateKey prk = kpf.generatePrivate(privSpec);

        OpenSSHPublicKeySpec edDsaPublicKeySpec = (OpenSSHPublicKeySpec)kpf.getKeySpec(pk, OpenSSHPublicKeySpec.class);
        OpenSSHPrivateKeySpec edDsaPrivateKeySpec = (OpenSSHPrivateKeySpec)kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);

        isEquals("Pk type", edDsaPublicKeySpec.getType(), "ssh-ed25519");
        isEquals("Spec Type", edDsaPrivateKeySpec.getFormat(), "OpenSSH");


        isTrue("EDPublic key not same", Arrays.areEqual(rawPub, edDsaPublicKeySpec.getEncoded()));

        // EdEc private keys include a random check int, so we check around it.
        byte[] enc = edDsaPrivateKeySpec.getEncoded();
        byte[] base = Hex.decode("6f70656e7373682d6b65792d763100000000046e6f6e65000000046e6f6e650000000000000001000000330000000b7373682d6564323535313900000020ce02695ed641ccb4961b7485c9605dfe0e972bf3befd9f9d4bd0dc9f0862c58500000088");
        byte[] tail = Hex.decode("0000000b7373682d6564323535313900000020ce02695ed641ccb4961b7485c9605dfe0e972bf3befd9f9d4bd0dc9f0862c58500000040f80531de477603ec2150aaeb33b5f2f92be6120f899118b0706fb8c7897c4824ce02695ed641ccb4961b7485c9605dfe0e972bf3befd9f9d4bd0dc9f0862c585000000000102030405");
        isTrue("EDPrivate key base not same", Arrays.areEqual(base, Arrays.copyOfRange(enc, 0, base.length)));
        isTrue("EDPrivate key tail not same", Arrays.areEqual(tail, Arrays.copyOfRange(enc, base.length + 8, enc.length)));

        isEquals("ssh-ed25519", edDsaPublicKeySpec.getType());
    }

    public String getName()
    {
        return "OpenSSHSpec";
    }

    public void performTest()
        throws Exception
    {
        testEncodingDSA();
        testEncodingRSA();
        testEncodingECDSA();
        testED25519();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OpenSSHSpecTests());
    }
}
