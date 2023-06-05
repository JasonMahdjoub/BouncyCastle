package com.distrimind.bouncycastle.pqc.crypto.picnic;

import com.distrimind.bouncycastle.util.Exceptions;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class LowmcConstantsL5
    extends LowmcConstants
{
    LowmcConstantsL5()
    {
        InputStream input = LowmcConstants.class.getResourceAsStream("lowmcL5.properties");
        Properties props = new Properties();

        // load a properties file
        try
        {
            props.load(input);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to load Picnic properties: " + e.getMessage(), e);
        }
        // Parameters for security level L5
        // Block/key size: 256
        // Rounds: 38
        linearMatrices = ReadFromProperty(props, "linearMatrices", 311296);
        roundConstants = ReadFromProperty(props, "roundConstants", 1216);
        keyMatrices = ReadFromProperty(props, "keyMatrices", 319488);

        LMatrix = new KMatrices(38, 256, 8, linearMatrices);
        KMatrix = new KMatrices(39, 256, 8, keyMatrices);
        RConstants = new KMatrices(38, 1, 8, roundConstants);

        // Parameters for security level L5, full nonlinear layer
        // Block/key size: 255
        // S-boxes: 85
        // Rounds: 4
        linearMatrices_full = ReadFromProperty(props, "linearMatrices_full", 32768);
        linearMatrices_inv = ReadFromProperty(props, "linearMatrices_inv", 32768);
        roundConstants_full = ReadFromProperty(props, "roundConstants_full", 128);
        keyMatrices_full = ReadFromProperty(props, "keyMatrices_full", 40960);
        keyMatrices_inv = ReadFromProperty(props, "keyMatrices_inv", 8160);

        LMatrix_full = new KMatrices(4, 255, 8, linearMatrices_full);
        LMatrix_inv = new KMatrices(4, 255, 8, linearMatrices_inv);
        KMatrix_full = new KMatrices(5, 255, 8, keyMatrices_full);
        KMatrix_inv = new KMatrices(1, 255, 8, keyMatrices_inv);
        RConstants_full = new KMatrices(4, 1, 8, roundConstants_full);
    }
}