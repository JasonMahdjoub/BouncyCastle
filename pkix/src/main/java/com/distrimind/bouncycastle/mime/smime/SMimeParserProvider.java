package com.distrimind.bouncycastle.mime.smime;

import java.io.IOException;
import java.io.InputStream;

import com.distrimind.bouncycastle.mime.BasicMimeParser;
import com.distrimind.bouncycastle.mime.Headers;
import com.distrimind.bouncycastle.mime.MimeParser;
import com.distrimind.bouncycastle.mime.MimeParserProvider;
import com.distrimind.bouncycastle.operator.DigestCalculatorProvider;

public class SMimeParserProvider
    implements MimeParserProvider
{
    private final String defaultContentTransferEncoding;
    private final DigestCalculatorProvider digestCalculatorProvider;

    public SMimeParserProvider(String defaultContentTransferEncoding, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public MimeParser createParser(InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
            SMimeUtils.autoBuffer(source));
    }

    public MimeParser createParser(Headers headers, InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
            headers, SMimeUtils.autoBuffer(source));
    }
}
