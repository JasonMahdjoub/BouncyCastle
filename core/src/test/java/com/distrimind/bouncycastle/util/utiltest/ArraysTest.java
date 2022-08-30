package com.distrimind.bouncycastle.util.utiltest;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.util.Arrays;

public class ArraysTest
    extends TestCase
{
    public void testConcatenate()
    {
        assertNull(Arrays.concatenate((byte[])null, (byte[])null));
        assertNull(Arrays.concatenate((int[])null, (int[])null));
    }
}
