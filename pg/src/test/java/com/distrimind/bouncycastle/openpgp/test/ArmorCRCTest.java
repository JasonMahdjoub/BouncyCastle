package com.distrimind.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.distrimind.bouncycastle.bcpg.ArmoredInputStream;
import com.distrimind.bouncycastle.bcpg.ArmoredOutputStream;
import com.distrimind.bouncycastle.openpgp.PGPLiteralData;
import com.distrimind.bouncycastle.openpgp.PGPLiteralDataGenerator;
import com.distrimind.bouncycastle.openpgp.PGPObjectFactory;
import com.distrimind.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.io.Streams;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class ArmorCRCTest
    extends SimpleTest
{

    private static final String WITHOUT_CRC = "" +
        "-----BEGIN PGP MESSAGE-----\n" +
        "\n" +
        "yxR0AAAAAABIZWxsbywgV29ybGQhCg==\n" +
        "-----END PGP MESSAGE-----\n";
    private static final String FAULTY_CRC = "" +
        "-----BEGIN PGP MESSAGE-----\n" +
        "\n" +
        "yxR0AAAAAABIZWxsbywgV29ybGQhCg==\n" +
        "=TRA9\n" +
        "-----END PGP MESSAGE-----";

    @Override
    public String getName()
    {
        return "ArmorCRCTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        generateArmorWithoutCRCSum();
        consumeArmorWithoutCRC();
    }

    private void generateArmorWithoutCRCSum()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = ArmoredOutputStream.builder()
            .enableCRC(false)
            .build(bOut);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(armorOut, PGPLiteralDataGenerator.TEXT,
            "", PGPLiteralData.NOW, new byte[512]);
        litOut.write(Strings.toByteArray("Hello, World!\n"));
        litOut.close();
        armorOut.close();

        isEquals(WITHOUT_CRC, Strings.fromByteArray(bOut.toByteArray()));
    }


    private void consumeArmorWithoutCRC()
        throws IOException
    {
        consumeSuccessfullyIgnoringCRCSum(WITHOUT_CRC);
        consumeSuccessfullyIgnoringCRCSum(FAULTY_CRC);
    }

    private void consumeSuccessfullyIgnoringCRCSum(String armor)
        throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toByteArray(armor));
        ArmoredInputStream armorIn = ArmoredInputStream.builder()
            .setParseForHeaders(true)
            .setIgnoreCRC(true)
            .build(bIn);


        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();
        InputStream litIn = literalData.getDataStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(litIn, bOut);
        litIn.close();
        armorIn.close();

        isEquals("Hello, World!\n", bOut.toString());
    }

    public static void main(String[] args)
    {
        runTest(new ArmorCRCTest());
    }
}
