package org.bouncycastle.cert.test;

import org.bouncycastle.bcutil.test.SimpleTest;
import org.bouncycastle.bcutil.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new AttrCertTest(),
        new AttrCertSelectorTest(),
        new CertTest(),
        new PKCS10Test()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
