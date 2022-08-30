package org.bouncycastle.oer.test;

import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new ExpansionTest(),
        new ExtensionTest(),
        
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
