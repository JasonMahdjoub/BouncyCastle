package com.distrimind.bouncycastle.mime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import com.distrimind.bouncycastle.cms.test.CMSTestUtil;
import com.distrimind.bouncycastle.util.Arrays;
import junit.framework.TestCase;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import com.distrimind.bouncycastle.cms.CMSAlgorithm;
import com.distrimind.bouncycastle.cms.CMSException;
import com.distrimind.bouncycastle.cms.CMSTypedStream;
import com.distrimind.bouncycastle.cms.OriginatorInformation;
import com.distrimind.bouncycastle.cms.RecipientInformation;
import com.distrimind.bouncycastle.cms.RecipientInformationStore;
import com.distrimind.bouncycastle.cms.SignerInformation;
import com.distrimind.bouncycastle.cms.SignerInformationStore;
import com.distrimind.bouncycastle.cms.jcajce.JcaSignerId;
import com.distrimind.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import com.distrimind.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import com.distrimind.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.mime.Headers;
import com.distrimind.bouncycastle.mime.MimeParser;
import com.distrimind.bouncycastle.mime.MimeParserContext;
import com.distrimind.bouncycastle.mime.MimeParserProvider;
import com.distrimind.bouncycastle.mime.smime.SMIMEEnvelopedWriter;
import com.distrimind.bouncycastle.mime.smime.SMIMESignedWriter;
import com.distrimind.bouncycastle.mime.smime.SMimeParserListener;
import com.distrimind.bouncycastle.mime.smime.SMimeParserProvider;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import com.distrimind.bouncycastle.util.Store;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.encoders.Base64;
import com.distrimind.bouncycastle.util.io.Streams;

public class TestSMIMESignEncrypt
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _signDN;
    private static KeyPair _signKP;

    private static String _reciDN;
    private static KeyPair _reciKP;

    private static X509Certificate _signCert;
    private static X509Certificate _reciCert;

    private static boolean _initialised = false;

    private static final byte[] simpleMessage = Strings.toByteArray(
        "Content-Type: text/plain; name=null; charset=us-ascii\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n" +
            "Content-Disposition: inline; filename=null\r\n" +
            "\r\n" +
            "Hello, world!\r\n");

    private static final byte[] simpleMessageContent = Strings.toByteArray(
        "Hello, world!\r\n");

    private static final byte[] testMultipartMessage = Base64.decode(
        "TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" +
            "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" +
            "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" +
            "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" +
            "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" +
            "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" +
            "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" +
            "wMTMyLS0NCg==");

    private static final byte[] testMultipartMessageContent = Base64.decode(
        "LS0tLS0tPV9QYXJ0XzBfMjYwMzk2Mzg2LjEzNTI5MDQ3NTAxMzINCkNvbnRlbnQtVHlwZTogdGV4dC9w" +
            "bGFpbjsgbmFtZT1udWxsOyBjaGFyc2V0PXVzLWFzY2lpDQpDb250ZW50LVRyYW5zZmVyLUVuY29kaW5n" +
            "OiA3Yml0DQpDb250ZW50LURpc3Bvc2l0aW9uOiBpbmxpbmU7IGZpbGVuYW1lPW51bGwNCg0KQ2lhbyBm" +
            "cm9tIHZpZW5uYQ0KLS0tLS0tPV9QYXJ0XzBfMjYwMzk2Mzg2LjEzNTI5MDQ3NTAxMzItLQ0K");

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            if (Security.getProvider("BC") == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            _initialised = true;

            //create certificate of the sender(signature certificate)
            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            //create certificate of the receiver (encryption certificate)
            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
        }
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    public void testSignThenEncrypt()
        throws Exception
    { 
      
        //output that will contain signed and encrypted content
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        SMIMEEnvelopedWriter.Builder envBldr = new SMIMEEnvelopedWriter.Builder();

        //specify encryption certificate
        envBldr.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        SMIMEEnvelopedWriter envWrt = envBldr.build(bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        OutputStream envOut = envWrt.getContentStream();

        SMIMESignedWriter.Builder sigBldr = new SMIMESignedWriter.Builder();

        //specify signature certificate
        sigBldr.addCertificate(new JcaX509CertificateHolder(_signCert));

        sigBldr.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA256withRSA", _signKP.getPrivate(), _signCert));

        //add the encryption stream to the signature stream
        SMIMESignedWriter sigWrt = sigBldr.build(envOut);

        OutputStream sigOut = sigWrt.getContentStream();

        sigOut.write(simpleMessage);
        
        //sign file using sender private key
        sigOut.close();
        
        //write full message to the byte array output stream before actually closing the SMIME Enveloped Writer (before this, bOut contains only the headers?)
        envOut.close();

        bOut.close();
        
        //
        // parse / decrypt and compare to original file 
        //
        final TestDoneFlag dataParsed = new TestDoneFlag();

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(new ReadOnceInputStream(bOut.toByteArray()));

        p.parse(new SMimeParserListener()
        {
            public void envelopedData(MimeParserContext parserContext, Headers headers, OriginatorInformation originator, RecipientInformationStore recipients)
                throws IOException, CMSException
            {
                RecipientInformation recipInfo = recipients.get(new JceKeyTransRecipientId(_reciCert));

                assertNotNull(recipInfo);
                
                //decrypt the file using the receiver's private key before verifying signature
                CMSTypedStream content = recipInfo.getContentStream(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()));

                MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());
                
                MimeParser p = provider.createParser(content.getContentStream());

                p.parse(new SMimeParserListener()
                {
                    public void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
                        throws IOException
                    {
                        byte[] content = Streams.readAll(inputStream);

                        assertTrue(Arrays.areEqual(simpleMessageContent, content));
                    }

                    public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
                        throws IOException, CMSException
                    {
                        SignerInformation signerInfo = signers.get(new JcaSignerId(_signCert));

                        assertNotNull(signerInfo);

                        Collection certCollection = certificates.getMatches(signerInfo.getSID());

                        Iterator certIt = certCollection.iterator();
                        X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

                        try
                        {
                            assertEquals(true, signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)));
                        }
                        catch (OperatorCreationException e)
                        {
                            throw new CMSException(e.getMessage(), e);
                        }
                        catch (CertificateException e)
                        {
                            throw new CMSException(e.getMessage(), e);
                        }

                        dataParsed.markDone();
                    }
                });
            }
        });

        assertTrue(dataParsed.isDone());
    }
}
