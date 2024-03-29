package com.distrimind.bouncycastle.openpgp.examples;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import com.distrimind.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import com.distrimind.bouncycastle.bcpg.ArmoredOutputStream;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.openpgp.PGPCompressedData;
import com.distrimind.bouncycastle.openpgp.PGPCompressedDataGenerator;
import com.distrimind.bouncycastle.openpgp.PGPEncryptedData;
import com.distrimind.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import com.distrimind.bouncycastle.openpgp.PGPEncryptedDataList;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPLiteralData;
import com.distrimind.bouncycastle.openpgp.PGPOnePassSignatureList;
import com.distrimind.bouncycastle.openpgp.PGPPrivateKey;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;
import com.distrimind.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import com.distrimind.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import com.distrimind.bouncycastle.openpgp.PGPUtil;
import com.distrimind.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import com.distrimind.bouncycastle.util.io.Streams;

/**
 * A simple utility class that encrypts/decrypts public key based
 * encryption large files.
 * <p>
 * To encrypt a file: KeyBasedLargeFileProcessor -e [-a|-ai] fileName publicKeyFile.<br>
 * If -a is specified the output file will be "ascii-armored".
 * If -i is specified the output file will be have integrity checking added.
 * <p>
 * To decrypt: KeyBasedLargeFileProcessor -d fileName secretKeyFile passPhrase.
 * <p>
 * Note 1: this example will silently overwrite files, nor does it pay any attention to
 * the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase
 * will have been used.
 * <p>
 * Note 2: this example generates partial packets to encode the file, the output it generates
 * will not be readable by older PGP products or products that don't support partial packet 
 * encoding.
 * <p>
 * Note 3: if an empty file name has been specified in the literal data object contained in the
 * encrypted packet a file with the name filename.out will be generated in the current working directory.
 */
public class KeyBasedLargeFileProcessor
{
    private static void decryptFile(
        String inputFileName,
        String keyFileName,
        char[] passwd,
        String defaultFileName)
        throws IOException, NoSuchProviderException
    {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        decryptFile(in, keyIn, passwd, defaultFileName);
        keyIn.close();
        in.close();
    }
    
    /**
     * decrypt the passed in message stream
     */
    private static void decryptFile(
        InputStream in,
        InputStream keyIn,
        char[]      passwd,
        String      defaultFileName)
        throws IOException, NoSuchProviderException
    {    
        in = PGPUtil.getDecoderStream(in);
        
        try
        {
            JcaPGPObjectFactory        pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList    enc;

            Object                  o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList)o;
            }
            else
            {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }
            
            //
            // find the secret key
            //
            Iterator                    it = enc.getEncryptedDataObjects();
            PGPPrivateKey               sKey = null;
            PGPPublicKeyEncryptedData   pbe = null;
            PGPSecretKeyRingCollection  pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
            
            while (sKey == null && it.hasNext())
            {
                pbe = (PGPPublicKeyEncryptedData)it.next();
                
                sKey = PGPExampleUtil.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }
            
            if (sKey == null)
            {
                throw new IllegalArgumentException("secret key for message not found.");
            }
            
            InputStream         clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
            
            JcaPGPObjectFactory    plainFact = new JcaPGPObjectFactory(clear);
            
            PGPCompressedData   cData = (PGPCompressedData)plainFact.nextObject();
    
            InputStream         compressedStream = new BufferedInputStream(cData.getDataStream());
            JcaPGPObjectFactory    pgpFact = new JcaPGPObjectFactory(compressedStream);
            
            Object              message = pgpFact.nextObject();
            
            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData)message;

                String outFileName = ld.getFileName();
                if (outFileName.length() == 0)
                {
                    outFileName = defaultFileName;
                }

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new FileOutputStream(outFileName);

                Streams.pipeAll(unc, fOut, 8192);

                fOut.close();
            }
            else if (message instanceof PGPOnePassSignatureList)
            {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected())
            {
                if (!pbe.verify())
                {
                    System.err.println("message failed integrity check");
                }
                else
                {
                    System.err.println("message integrity check passed");
                }
            }
            else
            {
                System.err.println("no message integrity check");
            }
        }
        catch (PGPException e)
        {
            System.err.println(e);
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    private static void encryptFile(
        String          outputFileName,
        String          inputFileName,
        String          encKeyFileName,
        boolean         armor,
        boolean         withIntegrityCheck)
        throws IOException, NoSuchProviderException, PGPException
    {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        PGPPublicKey encKey = PGPExampleUtil.readPublicKey(encKeyFileName);
        encryptFile(out, inputFileName, encKey, armor, withIntegrityCheck);
        out.close();
    }

    private static void encryptFile(
        OutputStream    out,
        String          fileName,
        PGPPublicKey    encKey,
        boolean         armor,
        boolean         withIntegrityCheck)
        throws IOException, NoSuchProviderException
    {    
        if (armor)
        {
            out = new ArmoredOutputStream(out);
        }
        
        try
        {
            PGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                    .setProvider("BC")
                    .setSecureRandom(new SecureRandom())
                    .setWithIntegrityPacket(withIntegrityCheck);
    
            PGPEncryptedDataGenerator   cPk = new PGPEncryptedDataGenerator(encryptorBuilder);
                
            cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            
            OutputStream                cOut = cPk.open(out, new byte[1 << 16]);
            
            PGPCompressedDataGenerator  comData = new PGPCompressedDataGenerator(
                                                                    PGPCompressedData.ZIP);
                                                                    
            PGPUtil.writeFileToLiteralData(comData.open(cOut), PGPLiteralData.BINARY, new File(fileName), new byte[1 << 16]);
            
            comData.close();
            
            cOut.close();

            if (armor)
            {
                out.close();
            }
        }
        catch (PGPException e)
        {
            System.err.println(e);
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length == 0)
        {
            System.err.println("usage: KeyBasedLargeFileProcessor -e|-d [-a|ai] file [secretKeyFile passPhrase|pubKeyFile]");
            return;
        }
        
        if (args[0].equals("-e"))
        {
            if (args[1].equals("-a") || args[1].equals("-ai") || args[1].equals("-ia"))
            {
                encryptFile(args[2] + ".asc", args[2], args[3], true, (args[1].indexOf('i') > 0));
            }
            else if (args[1].equals("-i"))
            {
                encryptFile(args[2] + ".bpg", args[2], args[3], false, true);
            }
            else
            {
                encryptFile(args[1] + ".bpg", args[1], args[2], false, false);
            }
        }
        else if (args[0].equals("-d"))
        {
            decryptFile(args[1], args[2], args[3].toCharArray(), new File(args[1]).getName() + ".out");
        }
        else
        {
            System.err.println("usage: KeyBasedLargeFileProcessor -d|-e [-a|ai] file [secretKeyFile passPhrase|pubKeyFile]");
        }
    }
}
